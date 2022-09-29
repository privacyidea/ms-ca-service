using Microsoft.Win32;

namespace CAService
{
    internal class Settings
    {
        public static string BIND_ADDRESS = "0.0.0.0";
        public static int BIND_PORT = 50061;
        // The certificates have to be in machine store NOT USER!!
        public static string SERVER_CERT_SUBJECT_NAME = "WIN-GG7JP259HMQ";
        public static string SERVER_CA_CERT_SUBJECT_NAME = "nilsca-WIN-GG7JP259HMQ-CA";

        public static string SERVER_CERT_THUMBPRINT = "ab5ff53b48ccd30615f790a226c9d37fb35cd388";
        public static string SERVER_CA_CERT_STORE = "root"; // "root" or "intermediate", default ??

        public static string CA_CERT_THUMBPRINT = "2a55d0f5a5541dd639b7c1718ed138f9a2d5698e";
        public static string SERVER_CERT_STORE = "My"; // necessary?

        public static bool SERVER_USE_UNSAFE_CREDENTIALS = true;
        public static bool SERVER_FORCE_CLIENT_AUTH = true;
        // removable
        public static string LDAP_DOMAIN = "";
        public static string LDAP_SERVER = "";

        private static string _registryPath = "SOFTWARE\\Netknights GmbH\\PrivacyIDEA-CA-Service";
        private readonly ILogger<PrivacyIDEACAService> _logger;

        public Settings(ILogger<PrivacyIDEACAService> logger)
        {
            _logger = logger;
        }

        private string? Read(string name)
        {
            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(_registryPath);
                if (key is not null)
                {
                    Object? o = key.GetValue(name);
                    if (o is not null)
                    {
                        return o as string;
                    }
                    else
                    {
                        _logger.LogInformation($"object for key {name} is null.");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogInformation("RegistryReader: " + ex.Message);
            }

            return "";
        }
    }
}
