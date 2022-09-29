namespace CAService;

public class PrivacyIDEACAService : BackgroundService
{
    private readonly ILogger<PrivacyIDEACAService> _logger;
    private GrpcServer? _grpcServer;

    public PrivacyIDEACAService(ILogger<PrivacyIDEACAService> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Settings settings = new(_logger);
        Thread t = new(RunGrpcServer);
        t.Start(settings);
        _logger.LogInformation($"Worker starting at: {DateTimeOffset.Now} in thread {Environment.CurrentManagedThreadId}");

        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(1000, stoppingToken);
        }

        if (_grpcServer is not null)
        {
            var task = _grpcServer?.Stop();
            if (task is not null)
            {
                await task;
            }
        }
        
        _logger.LogInformation("gRPC server stopped.");
    }

    private void RunGrpcServer(object? settings)
    {
        if (settings is Settings s)
        {
            _grpcServer = new GrpcServer(_logger, s);
            _grpcServer.Start();
        }
        else
        {
            _logger.LogInformation($"Unable to start GRPC server because settings are invalid");
        }
    }
}
