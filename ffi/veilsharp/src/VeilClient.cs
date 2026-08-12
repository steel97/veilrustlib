using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace VeilSharp;

/// <summary>
/// High-level async wrapper for VeilRust FFI
/// </summary>
public sealed class VeilClient : IDisposable
{
    private static readonly object InitLock = new();
    private static bool _isInitialized;
    private static VeilSharpNatives.VeilCallback? _callback;
    private static int _nextRequestId;

    private readonly ConcurrentDictionary<string, TaskCompletionSource<JsonDocument>> _pendingRequests = new();
    private bool _disposed;

    /// <summary>
    /// Initialize the native library. Must be called once before using VeilClient.
    /// </summary>
    public static void Initialize()
    {
        lock (InitLock)
        {
            if (_isInitialized)
                return;

            _callback = OnCallback;
            var result = VeilSharpNatives.VeilInit(_callback, IntPtr.Zero);
            if (result != 0)
            {
                var error = VeilSharpNatives.GetLastErrorString();
                throw new VeilException(result, $"Failed to initialize: {error}");
            }

            _isInitialized = true;
        }
    }

    /// <summary>
    /// Shutdown the native library. Should be called once when application exits.
    /// </summary>
    public static void Shutdown()
    {
        lock (InitLock)
        {
            if (!_isInitialized)
                return;

            VeilSharpNatives.VeilShutdown();
            _isInitialized = false;
            _callback = null;
        }
    }

    /// <summary>
    /// Get the native library version string
    /// </summary>
    public static string GetVersion()
    {
        return VeilSharpNatives.GetVersionString();
    }

    private static void OnCallback(IntPtr jsonPtr, nuint length, IntPtr userData)
    {
        try
        {
            var jsonBytes = new byte[length];
            Marshal.Copy(jsonPtr, jsonBytes, 0, (int)length);
            var json = Encoding.UTF8.GetString(jsonBytes);

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // Extract @extra field for request correlation
            if (!root.TryGetProperty("@extra", out var extraElement))
                return;

            var extra = extraElement.GetString();
            if (string.IsNullOrEmpty(extra))
                return;

            // Parse extra to get instance ID and request ID
            var parts = extra.Split(':', 2);
            if (parts.Length != 2)
                return;

            var instanceId = parts[0];
            var requestId = parts[1];

            // Find the instance and complete the request
            if (Instances.TryGetValue(instanceId, out var instance))
            {
                instance.CompleteRequest(requestId, json);
            }
        }
        catch
        {
            // Callback must not throw
        }
    }

    private static readonly ConcurrentDictionary<string, VeilClient> Instances = new();
    private readonly string _instanceId;

    public VeilClient()
    {
        if (!_isInitialized)
            throw new InvalidOperationException("VeilClient.Initialize() must be called first");

        _instanceId = Guid.NewGuid().ToString("N");
        Instances[_instanceId] = this;
    }

    private void CompleteRequest(string requestId, string json)
    {
        if (_pendingRequests.TryRemove(requestId, out var tcs))
        {
            try
            {
                var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                // Check for error response
                if (root.TryGetProperty("@type", out var typeElement) &&
                    typeElement.GetString() == "error")
                {
                    var code = root.GetProperty("code").GetInt32();
                    var message = root.GetProperty("message").GetString() ?? "Unknown error";
                    tcs.SetException(new VeilException(code, message));
                }
                else
                {
                    tcs.SetResult(doc);
                }
            }
            catch (Exception ex)
            {
                tcs.SetException(ex);
            }
        }
    }

    private async Task<JsonDocument> SendRequestAsync(object request, CancellationToken cancellationToken = default)
    {
        var requestId = Interlocked.Increment(ref _nextRequestId).ToString();
        var extra = $"{_instanceId}:{requestId}";

        var tcs = new TaskCompletionSource<JsonDocument>();
        _pendingRequests[requestId] = tcs;

        try
        {
            // Inject @extra field into request and rename __type to @type
            var json = JsonSerializer.Serialize(request);
            using var tempDoc = JsonDocument.Parse(json);
            var jsonObj = new Dictionary<string, object?>();

            foreach (var prop in tempDoc.RootElement.EnumerateObject())
            {
                var key = prop.Name == "__type" ? "@type" : prop.Name;
                jsonObj[key] = JsonSerializer.Deserialize<object>(prop.Value.GetRawText());
            }

            jsonObj["@extra"] = extra;
            var requestJson = JsonSerializer.Serialize(jsonObj);

            var result = VeilSharpNatives.VeilSend(requestJson);
            if (result != 0)
            {
                var error = VeilSharpNatives.GetLastErrorString();
                throw new VeilException(result, $"Failed to send request: {error}");
            }

            using (cancellationToken.Register(() => tcs.TrySetCanceled(cancellationToken)))
            {
                return await tcs.Task;
            }
        }
        catch
        {
            _pendingRequests.TryRemove(requestId, out _);
            throw;
        }
    }

    /// <summary>
    /// Create a new RPC client session
    /// </summary>
    public async Task<ulong> CreateClientAsync(
        string? rpcUrl = null,
        string? rpcUsername = null,
        string? rpcPassword = null,
        string? cachePath = null,
        ulong? timeoutMs = null,
        CancellationToken cancellationToken = default)
    {
        var request = new
        {
            __type = "createClient",
            rpc_url = rpcUrl,
            rpc_username = rpcUsername,
            rpc_password = rpcPassword,
            cache_path = cachePath,
            timeout_ms = timeoutMs
        };

        var response = await SendRequestAsync(request, cancellationToken);
        return response.RootElement.GetProperty("client_id").GetUInt64();
    }

    /// <summary>
    /// Close an RPC client session and free resources
    /// </summary>
    public async Task CloseClientAsync(ulong clientId, CancellationToken cancellationToken = default)
    {
        var request = new
        {
            __type = "closeClient",
            client_id = clientId
        };

        await SendRequestAsync(request, cancellationToken);
    }

    /// <summary>
    /// Derive stealth keys from a mnemonic seed phrase
    /// </summary>
    public async Task<JsonDocument> DeriveStealthKeysAsync(
        ulong clientId,
        string mnemonic,
        string? passphrase = null,
        uint? accountId = null,
        string? accountType = null,
        uint? index = null,
        CancellationToken cancellationToken = default)
    {
        var request = new
        {
            __type = "deriveStealthKeys",
            client_id = clientId,
            mnemonic,
            passphrase,
            account_id = accountId,
            account_type = accountType,
            index
        };

        return await SendRequestAsync(request, cancellationToken);
    }

    /// <summary>
    /// Validate an address and get its type
    /// </summary>
    public async Task<JsonDocument> ValidateAddressAsync(
        string address,
        CancellationToken cancellationToken = default)
    {
        var request = new
        {
            __type = "validateAddress",
            address
        };

        return await SendRequestAsync(request, cancellationToken);
    }

    /// <summary>
    /// Get balance and UTXOs for the current wallet
    /// </summary>
    public async Task<JsonDocument> GetBalanceAsync(
        ulong clientId,
        string? recoveryPolicy = null,
        CancellationToken cancellationToken = default)
    {
        var request = new
        {
            __type = "getBalance",
            client_id = clientId,
            recovery_policy = recoveryPolicy
        };

        return await SendRequestAsync(request, cancellationToken);
    }

    /// <summary>
    /// List UTXOs with optional filtering
    /// </summary>
    public async Task<JsonDocument> ListUtxosAsync(
        ulong clientId,
        ulong? minAmount = null,
        bool? onlySpendable = null,
        CancellationToken cancellationToken = default)
    {
        var request = new
        {
            __type = "listUtxos",
            client_id = clientId,
            min_amount = minAmount,
            only_spendable = onlySpendable
        };

        return await SendRequestAsync(request, cancellationToken);
    }

    /// <summary>
    /// Get transaction history
    /// </summary>
    public async Task<JsonDocument> GetTransactionHistoryAsync(
        ulong clientId,
        CancellationToken cancellationToken = default)
    {
        var request = new
        {
            __type = "getTransactionHistory",
            client_id = clientId
        };

        return await SendRequestAsync(request, cancellationToken);
    }

    /// <summary>
    /// Create a transaction (does not broadcast)
    /// </summary>
    public async Task<JsonDocument> CreateTransactionAsync(
        ulong clientId,
        object[] recipients,
        uint? ringSize = null,
        ulong? feePerKb = null,
        CancellationToken cancellationToken = default)
    {
        var request = new
        {
            __type = "createTransaction",
            client_id = clientId,
            recipients,
            ring_size = ringSize,
            fee_per_kb = feePerKb
        };

        return await SendRequestAsync(request, cancellationToken);
    }

    /// <summary>
    /// Broadcast a transaction to the network
    /// </summary>
    public async Task<JsonDocument> SendTransactionAsync(
        ulong clientId,
        string txHex,
        CancellationToken cancellationToken = default)
    {
        var request = new
        {
            __type = "sendTransaction",
            client_id = clientId,
            tx_hex = txHex
        };

        return await SendRequestAsync(request, cancellationToken);
    }

    /// <summary>
    /// Build and send a transaction in one call
    /// </summary>
    public async Task<JsonDocument> BuildAndSendTransactionAsync(
        ulong clientId,
        object[] recipients,
        uint? ringSize = null,
        ulong? feePerKb = null,
        CancellationToken cancellationToken = default)
    {
        var request = new
        {
            __type = "buildAndSendTransaction",
            client_id = clientId,
            recipients,
            ring_size = ringSize,
            fee_per_kb = feePerKb
        };

        return await SendRequestAsync(request, cancellationToken);
    }

    /// <summary>
    /// Clear the balance cache for the current wallet
    /// </summary>
    public async Task ClearCacheAsync(
        ulong clientId,
        CancellationToken cancellationToken = default)
    {
        var request = new
        {
            __type = "clearCache",
            client_id = clientId
        };

        await SendRequestAsync(request, cancellationToken);
    }

    /// <summary>
    /// Clear the sent transaction history
    /// </summary>
    public async Task ClearSentAsync(
        ulong clientId,
        CancellationToken cancellationToken = default)
    {
        var request = new
        {
            __type = "clearSent",
            client_id = clientId
        };

        await SendRequestAsync(request, cancellationToken);
    }

    /// <summary>
    /// Get blockchain information from the node
    /// </summary>
    public async Task<JsonDocument> GetBlockchainInfoAsync(
        ulong clientId,
        CancellationToken cancellationToken = default)
    {
        var request = new
        {
            __type = "getBlockchainInfo",
            client_id = clientId
        };

        return await SendRequestAsync(request, cancellationToken);
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        Instances.TryRemove(_instanceId, out _);

        foreach (var kvp in _pendingRequests)
        {
            kvp.Value.TrySetCanceled();
        }
        _pendingRequests.Clear();

        _disposed = true;
    }
}

/// <summary>
/// Exception thrown by VeilClient operations
/// </summary>
public class VeilException : Exception
{
    public int ErrorCode { get; }

    public VeilException(int errorCode, string message)
        : base(message)
    {
        ErrorCode = errorCode;
    }
}
