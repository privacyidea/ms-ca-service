using CAService;

IHost host = Host.CreateDefaultBuilder(args)
    .ConfigureServices(services =>
    {
        services.AddHostedService<PrivacyIDEACAService>();

    })
    .UseWindowsService(options =>
    {
        options.ServiceName = "PrivacyIDEA CA Service";
    })
    .ConfigureLogging(logging =>
    {
        logging.AddFile(Settings.LOG_FILE_PATH + "\\{Date}.txt", outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff} {Level:u3}] {Message} {NewLine}{Exception}");
    })
    .Build();

await host.RunAsync();
