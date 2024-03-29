using Grpc.Core;
using Grpc.Core.Logging;

namespace CAService;

public class PrivacyIDEACAService : BackgroundService
{
    private readonly LogWrapper _logger;
    private GrpcServer? _grpcServer;

    public PrivacyIDEACAService(ILogger<PrivacyIDEACAService> logger)
    {
        _logger = new(logger);
        _logger.LogEnabled = Settings.GetBool("debug_log", _logger);
        GrpcEnvironment.SetLogger(new TextWriterLogger(new TextWriterImpl(_logger)));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            Thread t = new(RunGrpcServer);
            t.Start();
        }
        catch (Exception e)
        {
            _logger.Error($"Unable to start gRPC server: {e.Message}");
        }
        _logger.Log($"PrivacyIDEA MS CA Service starting at: {DateTimeOffset.Now} in thread {Environment.CurrentManagedThreadId}");
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

        _logger.Log("gRPC server stopped.");
    }

    private void RunGrpcServer()
    {
        _grpcServer = new GrpcServer(_logger);
        _grpcServer.Start();
    }
}
