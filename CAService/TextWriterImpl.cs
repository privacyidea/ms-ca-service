using System.Text;

namespace CAService
{
    internal class TextWriterImpl : TextWriter
    {
        public override Encoding Encoding => Encoding.UTF8;

        private readonly LogWrapper _logger;
        public TextWriterImpl(LogWrapper logger)
        {
            _logger = logger;
        }

        public override void Write(string? value)
        {
            if (!string.IsNullOrEmpty(value) && value != Environment.NewLine)
            {
                _logger.Log(value);
            }
        }
    }
}
