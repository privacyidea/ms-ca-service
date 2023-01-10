using System.DirectoryServices;
using System.Security.Cryptography.X509Certificates;

namespace CAService
{
    /// <summary>
    /// Copied from https://github.com/GhostPack/Certify/blob/main/Certify/Domain/CertificateAuthority.cs
    /// </summary>

    // From certca.h in the Windows SDK
    [Flags]
    public enum PkiCertificateAuthorityFlags : uint
    {
        NO_TEMPLATE_SUPPORT = 0x00000001,
        SUPPORTS_NT_AUTHENTICATION = 0x00000002,
        CA_SUPPORTS_MANUAL_AUTHENTICATION = 0x00000004,
        CA_SERVERTYPE_ADVANCED = 0x00000008,
    }

    public class CertificateAuthority : ADObject, IDisposable
    {
        public string? Name { get; }
        public string? DomainName { get; }

        public Guid? Guid { get; }
        public PkiCertificateAuthorityFlags? Flags { get; }
        public List<X509Certificate2>? Certificates { get; private set; }


        private bool _disposed;
        public CertificateAuthority(string distinguishedName, string? name, string? domainName, Guid? guid, PkiCertificateAuthorityFlags? flags, List<X509Certificate2>? certificates, ActiveDirectorySecurity? securityDescriptor)
            : base(distinguishedName, securityDescriptor)
        {
            Name = name;
            DomainName = domainName;
            Guid = guid;
            Flags = flags;
            Certificates = certificates;
        }

        ~CertificateAuthority()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            // This object will be cleaned up by the Dispose method. 
            // Therefore, you should call GC.SupressFinalize to 
            // take this object off the finalization queue 
            // and prevent finalization code for this object 
            // from executing a second time.
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            // Check to see if Dispose has already been called. 
            if (_disposed) return;

            if (disposing)
            {
                // Dispose managed resources.

                // https://snede.net/the-most-dangerous-constructor-in-net/
                if (Certificates != null && Certificates.Any())
                {
                    Certificates.ForEach(c => c.Reset());
                    Certificates = new List<X509Certificate2>();
                }
            }

            _disposed = true;
        }
    }
}
