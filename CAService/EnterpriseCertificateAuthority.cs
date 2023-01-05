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
    }
}
