using System.Runtime.InteropServices;

namespace VeilSharp;

/// <summary>
/// Native P/Invoke bindings for veilrustffi library
/// </summary>
public static partial class VeilSharpNatives
{
    private const string LibraryName = "veilrustffi";

    #region Error Codes

    /// <summary>Success</summary>
    public const int VEIL_OK = 0;

    /// <summary>Invalid JSON format in request</summary>
    public const int VEIL_ERROR_INVALID_JSON = -1;

    /// <summary>Invalid client ID provided</summary>
    public const int VEIL_ERROR_INVALID_CLIENT_ID = -2;

    /// <summary>Runtime not initialized</summary>
    public const int VEIL_ERROR_NOT_INITIALIZED = -3;

    /// <summary>Runtime already initialized</summary>
    public const int VEIL_ERROR_ALREADY_INITIALIZED = -4;

    /// <summary>Callback function is null</summary>
    public const int VEIL_ERROR_CALLBACK_NULL = -5;

    /// <summary>Invalid input parameter (400)</summary>
    public const int ERROR_CODE_INVALID_INPUT = 400;

    /// <summary>Resource not found (404)</summary>
    public const int ERROR_CODE_NOT_FOUND = 404;

    /// <summary>Internal server error (500)</summary>
    public const int ERROR_CODE_INTERNAL = 500;

    /// <summary>RPC error (503)</summary>
    public const int ERROR_CODE_RPC = 503;

    /// <summary>Insufficient balance (507)</summary>
    public const int ERROR_CODE_INSUFFICIENT_BALANCE = 507;

    #endregion

    #region Callback Delegate

    /// <summary>
    /// Callback function signature for receiving JSON responses
    /// </summary>
    /// <param name="json">Pointer to JSON response string</param>
    /// <param name="len">Length of JSON string in bytes</param>
    /// <param name="userData">User data pointer passed to veil_init</param>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void VeilCallback(IntPtr json, nuint len, IntPtr userData);

    #endregion

    #region Native Methods

    /// <summary>
    /// Initialize the Veil FFI runtime with a callback function
    /// </summary>
    /// <param name="callback">Function pointer to receive JSON responses</param>
    /// <param name="userData">Opaque pointer passed back to callback</param>
    /// <returns>
    /// VEIL_OK (0) on success,
    /// VEIL_ERROR_CALLBACK_NULL if callback is null,
    /// VEIL_ERROR_ALREADY_INITIALIZED if already initialized
    /// </returns>
    /// <remarks>
    /// The callback must be thread-safe and must not throw exceptions.
    /// Keep a reference to the callback delegate to prevent garbage collection.
    /// </remarks>
    [LibraryImport(LibraryName, EntryPoint = "veil_init")]
    [UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial int VeilInit(VeilCallback callback, IntPtr userData);

    /// <summary>
    /// Send a JSON request to the Veil FFI runtime
    /// </summary>
    /// <param name="jsonRequest">Null-terminated JSON string</param>
    /// <returns>
    /// VEIL_OK (0) on success (response will arrive via callback),
    /// VEIL_ERROR_NOT_INITIALIZED if runtime not initialized,
    /// VEIL_ERROR_INVALID_JSON if JSON parsing fails
    /// </returns>
    /// <remarks>
    /// The response is delivered asynchronously via the callback registered with veil_init.
    /// The jsonRequest pointer must be valid and null-terminated.
    /// </remarks>
    [LibraryImport(LibraryName, EntryPoint = "veil_send", StringMarshalling = StringMarshalling.Utf8)]
    [UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial int VeilSend([MarshalAs(UnmanagedType.LPUTF8Str)] string jsonRequest);

    /// <summary>
    /// Shutdown the Veil FFI runtime and close all clients
    /// </summary>
    /// <remarks>
    /// This function blocks until all pending requests are completed.
    /// Must be called from the same thread that called veil_init.
    /// After shutdown, veil_init must be called again before using the library.
    /// </remarks>
    [LibraryImport(LibraryName, EntryPoint = "veil_shutdown")]
    [UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial void VeilShutdown();

    /// <summary>
    /// Get the last error message from a failed synchronous call
    /// </summary>
    /// <returns>Pointer to null-terminated error string, valid until next FFI call</returns>
    /// <remarks>
    /// The returned pointer is thread-local and must not be freed by the caller.
    /// Use Marshal.PtrToStringUTF8 to convert to a managed string.
    /// </remarks>
    [LibraryImport(LibraryName, EntryPoint = "veil_last_error")]
    [UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial IntPtr VeilLastError();

    /// <summary>
    /// Get the version of the FFI library
    /// </summary>
    /// <returns>Pointer to static null-terminated version string</returns>
    /// <remarks>
    /// The returned pointer is valid for the lifetime of the program.
    /// Use Marshal.PtrToStringUTF8 to convert to a managed string.
    /// </remarks>
    [LibraryImport(LibraryName, EntryPoint = "veil_version")]
    [UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial IntPtr VeilVersion();

    #endregion

    #region Helper Methods

    /// <summary>
    /// Get the last error message as a managed string
    /// </summary>
    /// <returns>Error message string, or empty string if none</returns>
    public static string GetLastErrorString()
    {
        var ptr = VeilLastError();
        return ptr != IntPtr.Zero ? Marshal.PtrToStringUTF8(ptr) ?? string.Empty : string.Empty;
    }

    /// <summary>
    /// Get the library version as a managed string
    /// </summary>
    /// <returns>Version string</returns>
    public static string GetVersionString()
    {
        var ptr = VeilVersion();
        return ptr != IntPtr.Zero ? Marshal.PtrToStringUTF8(ptr) ?? "unknown" : "unknown";
    }

    #endregion
}