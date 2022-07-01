using Microsoft.Win32;
using System.DirectoryServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace CAService
{
    /// <summary>
    /// Adapted from https://github.com/GhostPack/Certify/blob/main/Certify/Domain/EnterpriseCertificateAuthority.cs
    /// </summary>
    ///

    public class EnterpriseCertificateAuthority : CertificateAuthority
    {
        public List<string>? Templates { get; }
        public string? DnsHostname { get; }
        public string? FullName => $"{DnsHostname}\\{Name}";

        public EnterpriseCertificateAuthority(string distinguishedName, string? name, string? domainName, Guid? guid, string? dnsHostname, PkiCertificateAuthorityFlags? flags, List<X509Certificate2>? certificates, ActiveDirectorySecurity? securityDescriptor, List<string>? templates)
            : base(distinguishedName, name, domainName, guid, flags, certificates, securityDescriptor)
        {
            DnsHostname = dnsHostname;
            Templates = templates;
        }

        public ActiveDirectorySecurity? GetServerSecurityFromRegistry()
        {
            if (DnsHostname == null) throw new NullReferenceException("DnsHostname is null");
            if (Name == null) throw new NullReferenceException("Name is null");

            //  NOTE: this appears to usually work, even if admin rights aren't available on the remote CA server
            RegistryKey baseKey;
            try
            {
                baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, DnsHostname);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[X] Could not connect to the HKLM hive - {e.Message}");
                return null;
            }

            byte[] security;
            try
            {
                var key = baseKey.OpenSubKey($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{Name}");
                security = (byte[])key.GetValue("Security");
            }
            catch (SecurityException e)
            {
                Console.WriteLine($"[X] Could not access the 'Security' registry value: {e.Message}");
                return null;
            }

            var securityDescriptor = new ActiveDirectorySecurity();
            securityDescriptor.SetSecurityDescriptorBinaryForm(security, AccessControlSections.All);

            return securityDescriptor;
        }

        public RawSecurityDescriptor? GetEnrollmentAgentSecurity()
        {
            //  NOTE: this appears to work even if admin rights aren't available on the remote CA server...
            RegistryKey baseKey;
            try
            {
                baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, DnsHostname ?? "No DnsHostname available");
            }
            catch (Exception e)
            {
                throw new Exception($"Could not connect to the HKLM hive - {e.Message}");
            }

            byte[]? security = null;
            try
            {
                var key = baseKey.OpenSubKey($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{Name}");
                if (key is not null)
                {
                    var tmp = key.GetValue("EnrollmentAgentRights");
                    if (tmp is not null)
                    {
                        security = (byte[])tmp;
                    }
                }

            }
            catch (SecurityException e)
            {
                throw new Exception($"Could not access the 'EnrollmentAgentRights' registry value: {e.Message}");
            }

            return security == null ? null : new RawSecurityDescriptor(security, 0);
        }


        public bool IsUserSpecifiesSanEnabled()
        {
            if (DnsHostname == null) throw new NullReferenceException("DnsHostname is null");
            if (Name == null) throw new NullReferenceException("Name is null");

            // ref- https://blog.keyfactor.com/hidden-dangers-certificate-subject-alternative-names-sans
            //  NOTE: this appears to usually work, even if admin rights aren't available on the remote CA server
            RegistryKey baseKey;
            try
            {
                baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, DnsHostname);
            }
            catch (Exception e)
            {
                throw new Exception($"Could not connect to the HKLM hive - {e.Message}");
            }

            int editFlags;
            try
            {
                var key = baseKey.OpenSubKey($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{Name}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy");
                editFlags = (int)key.GetValue("EditFlags");
            }
            catch (SecurityException e)
            {
                throw new Exception($"Could not access the EditFlags registry value: {e.Message}");
            }

            // 0x00040000 -> EDITF_ATTRIBUTESUBJECTALTNAME2
            return (editFlags & 0x00040000) == 0x00040000;
        }


    }
}
