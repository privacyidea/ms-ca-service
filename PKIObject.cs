using System.DirectoryServices;
using System.Security.AccessControl;

namespace CAService
{
    /// <summary>
    /// Copied from https://github.com/GhostPack/Certify/blob/main/Certify/Domain/PKIObject.cs
    /// </summary>
    class PKIObjectACE
    {
        public string? Type { get; }
        public string? Rights { get; }
        public Guid? ObjectType { get; }
        public string? Principal { get; }

        public PKIObjectACE(AccessControlType? type, ActiveDirectoryRights? rights, Guid? objectType, string? principal)
        {
            Type = type.ToString();
            Rights = rights.ToString();
            ObjectType = objectType;
            Principal = principal;
        }
    }

    public class PKIObject : ADObject
    {
        public PKIObject(string? name, string? domainName, string distinguishedName, ActiveDirectorySecurity? securityDescriptor)
            : base(distinguishedName, securityDescriptor)
        {
            Name = name;
            DomainName = domainName;
            DistinguishedName = distinguishedName;
        }
        public string? Name { get; }
        public string? DomainName { get; }
    }
}
