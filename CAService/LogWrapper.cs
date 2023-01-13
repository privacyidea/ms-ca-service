namespace CAService
{
    public class LogWrapper
    {
        private readonly ILogger<PrivacyIDEACAService> _logger;
        public bool LogEnabled = true;

        public LogWrapper(ILogger<PrivacyIDEACAService> logger)
        {
            _logger = logger;
        }

        public void Log(string? message)
        {
            if (LogEnabled && !string.IsNullOrEmpty(message) && message != Environment.NewLine)
            {
                _logger.LogInformation(message);
            }
        }

        public void Error(string? message)
        {
            if (LogEnabled && !string.IsNullOrEmpty(message) && message != Environment.NewLine)
            {
                _logger.LogError(message);
            }
        }
    }
}
