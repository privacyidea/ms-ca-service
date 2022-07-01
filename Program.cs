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
       //logging.AddFilter("Grpc", LogLevel.Debug);
        logging.AddFile("Logs/{Date}.txt", outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff} {Level:u3}] {Message} {NewLine}{Exception}");
        //logging.AddProvider()
        
    })
    .Build();

await host.RunAsync();
