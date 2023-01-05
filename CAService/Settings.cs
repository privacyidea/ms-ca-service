using Microsoft.Win32;

namespace CAService
{
    // Retrieves settings from the registry
    internal class Settings
    {
        public static string BIND_ADDRESS = "0.0.0.0";
        public static string LOG_FILE_PATH = "C:\\Program Files\\PrivacyIDEA CA Service\\logs";
        private static readonly string _registryPath = "SOFTWARE\\Netknights GmbH\\PrivacyIDEA CA Service";

        public static string? GetString(string name, LogWrapper? logger = null)
        {
            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(_registryPath);
                if (key is not null)
                {
                    Object? o = key.GetValue(name);
                    if (o is not null)
                    {
                        return o.ToString();
                    }
                    else
                    {
                        logger?.Log($"Object for key {name} is null.");
                    }
                }
            }
            catch (Exception ex)
            {
                logger?.Error("RegistryReader: " + ex.Message);
            }

            return "";
        }

        // The registry entry must be excatly "1" for this to return true
        public static bool GetBool(string name, LogWrapper? logger = null)
        {
            return GetString(name, logger) == "1";
        }
    }
}
