# Building the MSI
The Installer project does not have a reference to the CA Service project because MSBuild does not support resolving COM references, which are contained in the CAService project. Therefore, to build this installer, the CA Service has to be published manually beforehand, using the FolderPublish profile provided. Right click on the CAService project in VS and select publish. Publish does not equal building and procudes binaries in a different location that is referenced in the Installer project.