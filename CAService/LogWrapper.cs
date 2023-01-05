namespace CAService
{
    public class LogWrapper
    {
        private readonly ILogger<PrivacyIDEACAService> _logger;
        public bool LogEnabled = true;
        public LogWrapper(ILogger<PrivacyIDEACAService> logger)
        {
            _logger = logger;
            //LogEnabled = Settings.GetBool("debug_log", this);
            
        }

        public void Log(string? message)
        {
            if (true && message is not null)
            {
                _logger.LogInformation(message);
            }
        }

        public void Error(string? message)
        {
            if (true && message is not null)
            {
                _logger.LogError(message);
            }
        }
    }
}
