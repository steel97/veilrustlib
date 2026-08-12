using VeilSharp;

Console.WriteLine("=== Cache Performance Comparison ===");
Console.WriteLine($"Veil FFI Version: {VeilClient.GetVersion()}");
Console.WriteLine();

string mnemonic = System.IO.File.ReadAllText("mnemonic.txt");

VeilClient.Initialize();
using var client = new VeilClient();
var clientId = await client.CreateClientAsync(cachePath: "sharpcache.redb");
var res = await client.DeriveStealthKeysAsync(clientId, mnemonic, accountType: "Stealth", accountId: 0, index: 1, cancellationToken: default);
Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(res));

var bchInfo = await client.GetBlockchainInfoAsync(clientId, default);
Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(bchInfo));

var balanceRes = await client.GetBalanceAsync(clientId, "Rewind(50)", default);
var balance = balanceRes.RootElement.GetProperty("total_balance").GetDouble();
var txes = balanceRes.RootElement.GetProperty("transactions").EnumerateArray();
Console.WriteLine(balance + " VEIL");
Console.WriteLine(txes.Count() + " transactions");

//Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(balanceRes));

var txHistory = await client.GetTransactionHistoryAsync(clientId, default);
//Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(txHistory));

Console.WriteLine("done");
Console.ReadLine();

await client.CloseClientAsync(clientId, default);

VeilClient.Shutdown();