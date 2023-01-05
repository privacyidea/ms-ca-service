using System.DirectoryServices;

namespace CAService
{
    /// <summary>
    /// From https://github.com/GhostPack/Certify/blob/main/Certify/Domain/ADObject.cs
    /// </summary>
    public class ADObject
    {
        public string DistinguishedName { get; set; }
        public ActiveDirectorySecurity? SecurityDescriptor { get; set; }
        public ADObject(string distinguishedName, ActiveDirectorySecurity? securityDescriptor)
        {
            DistinguishedName = distinguishedName;
            SecurityDescriptor = securityDescriptor;
        }
    }
}
