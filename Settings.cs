using Microsoft.Win32;

namespace CAService
{
    internal class Settings
    {
        public static string BIND_ADDRESS = "0.0.0.0";
        public static int BIND_PORT = 50061;
        // The certificates have to be in machine store NOT USER!!
        public static string SERVER_CERT_SUBJECT_NAME = "WIN-VOVT2IPOAET";
        public static string SERVER_CA_CERT_SUBJECT_NAME = "MyRootCA";

        public static string SERVER_CA_CERT_STORE = "root"; // "root" or "intermediate", default ??
        public static string SERVER_CERT_STORE = "My"; // necessary?
        public static bool SERVER_USE_UNSAFE_CREDENTIALS = false;
        public static bool SERVER_FORCE_CLIENT_AUTH = false;
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
