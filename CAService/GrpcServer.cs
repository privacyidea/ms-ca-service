using Grpc;
using Grpc.Core;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static Grpc.CAService;

namespace CAService
{
    internal class GrpcServer : CAServiceBase
    {
        private Server? _server;
        private readonly LogWrapper _logger;
        private readonly LdapOperations _ldapOp;
        private readonly CertOperations _certOps;

        public Dictionary<string, string> options = new();

        public GrpcServer(LogWrapper logger)
        {
            _logger = logger;
            _certOps = new CertOperations(logger);

            _ldapOp = new LdapOperations("", "")
            {
                _logger = _logger
            };

            SetupServer();
        }

        private X509Certificate2Collection GetCertificateByThumbprint(string thumbprint, StoreName storeName)
        {
            X509Store store = new(storeName, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection collection = store.Certificates;
            var fcollection = collection.Find(X509FindType.FindByThumbprint, thumbprint, true);
            store.Close();
            return fcollection;
        }

        private string GetPublicKeyPEM(X509Certificate2 certificate)
        {
            var b = certificate.Export(X509ContentType.Cert);
            return new string(PemEncoding.Write("CERTIFICATE", b));
        }

        private void SetupServer()
        {
            ServerCredentials credentials = ServerCredentials.Insecure;

            if (!Settings.GetBool("use_unsafe_connection", _logger))
            {
                _logger.Log("Setting up secure connection...");
                // Get the CA cert from the store
                string? caCertThumb = Settings.GetString("ca_cert_thumbprint", _logger);
                if (string.IsNullOrEmpty(caCertThumb))
                {
                    _logger.Log($"No thumbprint for CA certificate configured, aborting server start.");
                    return;
                }

                var caCertCandidates = GetCertificateByThumbprint(caCertThumb, StoreName.Root);
                if (caCertCandidates.Count == 0)
                {
                    _logger.Error($"Unable to find CA cert with thumbprint '{caCertThumb}' in cert store 'root'.");
                    return;
                }
                X509Certificate2? caCert = caCertCandidates[0];
                string caCertPEM = GetPublicKeyPEM(caCert);

                // Get the server cert from the store
                string? serverCertThumb = Settings.GetString("server_cert_thumbprint", _logger);
                if (string.IsNullOrEmpty(serverCertThumb))
                {
                    _logger.Log($"No thumbprint for the server certificate configured, aborting server start.");
                    return;
                }

                var serverCertCandidates = GetCertificateByThumbprint(serverCertThumb, StoreName.My);
                if (serverCertCandidates.Count == 0)
                {
                    _logger.Error($"Unable to find server cert with thumbprint '{serverCertThumb}' in cert store 'personal'.");
                    return;
                }
                X509Certificate2? serverCert = serverCertCandidates[0];

                // The server certificate needs to contain the private key
                if (!serverCert.HasPrivateKey)
                {
                    _logger.Log("Server certificate does not contain the private key or the private key can not be used. " +
                        "Make sure the private key of this certificate is exportable. Aborting server start.");
                    return;
                }

                string pemPrivateKey = "";
                string algo = serverCert.GetKeyAlgorithm();
                Oid oid = Oid.FromOidValue(algo, OidGroup.All);
                if (oid.FriendlyName == "RSA")
                {
                    var rsaPrivateKey = serverCert.GetRSAPrivateKey();
                    if (rsaPrivateKey != null)
                    {
                        var privateKeyBytes = rsaPrivateKey.ExportPkcs8PrivateKey();
                        pemPrivateKey = new(PemEncoding.Write("PRIVATE KEY", privateKeyBytes));
                    }
                }
                else
                {
                    // TODO check other algorithms
                    _logger.Error($"Unsupported server key algorithm: {oid.FriendlyName}");
                    return;
                }

                string pemPublicKey = GetPublicKeyPEM(serverCert);
                KeyCertificatePair keypair = new(pemPublicKey, pemPrivateKey);
                //_logger.Log($"Credentials for server:\nCA Cert:\n{caCertPEM}\n\nServer Certificate:\n{pemPublicKey}\n\nPrivate Key:\n{pemPrivateKey}");
                SslClientCertificateRequestType clientReqType = Settings.GetBool("force_client_auth", _logger)
                    ? SslClientCertificateRequestType.RequestAndRequireAndVerify : SslClientCertificateRequestType.RequestAndVerify;
                credentials = new SslServerCredentials(new List<KeyCertificatePair>() { keypair }, caCertPEM, clientReqType);
                _logger.Log("Starting server with secure credentials, forceClientAuth=" + clientReqType.ToString("G"));
            }
            else
            {
                _logger.Log("Starting server with insecure credentials...");
            }

            string? sPort = Settings.GetString("port");
            if (string.IsNullOrEmpty(sPort))
            {
                _logger.Log("No port configured. This setting is required! Aborting server start.");
                return;
            }
            int port;
            try
            {
                port = Int32.Parse(sPort);
            }
            catch (Exception ex)
            {
                _logger.Error($"Unable to convert 'port' setting ({sPort}) to int: {ex}");
                return;
            }

            _server = new Server
            {
                Ports = { new ServerPort(Settings.BIND_ADDRESS, port, credentials) },
                Services = { BindService(this) },

            };
            var host = _server.Ports.ElementAt(0).Host;
            port = _server.Ports.ElementAt(0).Port;
            _logger.Log($"Starting server at {host} and port {port} in thread {Environment.CurrentManagedThreadId}");
        }

        /// <summary>
        /// Throws IOException if port could not be bound
        /// </summary>
        public void Start()
        {
            _server?.Start();
        }

        public Task? Stop()
        {
            return _server?.KillAsync();
        }

        public override Task<GetCertificateValidityReply> GetCertificateValidity(GetCertificateValidityRequest request, ServerCallContext context)
        {
            _logger.Log($"GetCertificateValidity for {request.SerialNumber} from CA {request.CaName}");

            var reply = new GetCertificateValidityReply { Status = new() };
            if (string.IsNullOrEmpty(request.CaName) || string.IsNullOrEmpty(request.SerialNumber))
            {
                string errorMsg = "Missing CA Name or Serial!";
                _logger.Error($"GetCertificateValidity error: {errorMsg}");
                reply.Status = StatusGenericError(errorMsg);
                return Task.FromResult(reply);
            }

            int dispositon;
            try
            {
                dispositon = _certOps.GetCertificateValidity(request.CaName, request.SerialNumber);
            }
            catch (COMException comex)
            {
                _logger.Error($"IsValidCertificate encountered a COMException:\n{comex.Message}, Code: {comex.ErrorCode}\n{comex.StackTrace}");
                reply.Status.Code = comex.ErrorCode;
                reply.Status.Message = comex.Message;
                return Task.FromResult(reply);
            }

            if (Enum.IsDefined(typeof(CertificateValidity), dispositon))
            {
                reply.Validity = (CertificateValidity)dispositon;
            }
            else
            {
                string errorMsg = $"Received unknown certificate dispositon: {dispositon}";
                _logger.Error($"IsValidCertificate error: {errorMsg}");
                reply.Status = StatusGenericError(errorMsg);
                return Task.FromResult(reply);
            }

            _logger.Log($"Returning dispositon: {reply.Validity:G}");
            return Task.FromResult(reply);
        }

        public override Task<RevokeCertificateReply> RevokeCertificate(RevokeCertificateRequest request, ServerCallContext context)
        {
            _logger.Log($"RevokeCertificate from CA {request.CaName} with serial {request.SerialNumber} for reason {request.Reason} at time {request.Date}");

            var reply = new RevokeCertificateReply { Status = new() };

            if (string.IsNullOrEmpty(request.CaName) || string.IsNullOrEmpty(request.SerialNumber))
            {
                string errorMsg = "Missing CA Name or Serial for revocation!";
                _logger.Error($"RevokeCertificate error: {errorMsg}");
                reply.Status = StatusGenericError(errorMsg);
                return Task.FromResult(reply);
            }

            // Convert revocation reason and date in usable formats
            (int reason, string desc) = ResolveRevocationReason(request.Reason);
            if (reason > 6)
            {
                string errorMsg = $"Invalid revocation reason: {reason}";
                _logger.Error(errorMsg);
                reply.Status = StatusGenericError(errorMsg);
                return Task.FromResult(reply);
            }

            DateTime revocationTime = DateTime.Now;
            if (request.Date != 0)
            {
                revocationTime = DateTimeOffset.FromUnixTimeMilliseconds(request.Date).DateTime;
                if (revocationTime < DateTime.Now)
                {
                    string errorMsg = $"Revocation time in the past: {revocationTime}";
                    _logger.Error(errorMsg);
                    reply.Status = StatusGenericError(errorMsg);
                    return Task.FromResult(reply);
                }
            }

            _logger.Log($"Revoking certificate at {revocationTime} for reason {desc}");

            try
            {
                _certOps.RevokeCertificate(request.CaName, request.SerialNumber, reason, revocationTime);
            }
            catch (COMException comex)
            {
                _logger.Error($"RevokeCertificate encountered a COMException:\n{comex.Message}, Code: {comex.ErrorCode}\n{comex.StackTrace}");
                reply.Status.Code = comex.ErrorCode;
                reply.Status.Message = comex.Message;
                return Task.FromResult(reply);
            }


            return Task.FromResult(reply);
        }

        private Grpc.Status StatusGenericError(string msg)
        {
            return new()
            {
                Code = 1,
                Message = msg
            };
        }

        private (int, string) ResolveRevocationReason(RevokationReason reason)
        {
            switch (reason)
            {
                case RevokationReason.Unspecified: return (CertOperations.CRL_REASON_UNSPECIFIED, "CRL_REASON_UNSPECIFIED");
                case RevokationReason.KeyCompromise: return (CertOperations.CRL_REASON_KEY_COMPROMISE, "CRL_REASON_KEY_COMPROMISE");
                case RevokationReason.CaCompromise: return (CertOperations.CRL_REASON_CA_COMPROMISE, "CRL_REASON_CA_COMPROMISE");
                case RevokationReason.AffiliationChanged: return (CertOperations.CRL_REASON_AFFILIATION_CHANGED, "CRL_REASON_AFFILIATION_CHANGED");
                case RevokationReason.Superseded: return (CertOperations.CRL_REASON_SUPERSEDED, "CRL_REASON_SUPERSEDED");
                case RevokationReason.CessationOfOperation: return (CertOperations.CRL_REASON_CESSATION_OF_OPERATION, "CRL_REASON_CESSATION_OF_OPERATION");
                case RevokationReason.CertificateHold: return (CertOperations.CRL_REASON_CERTIFICATE_HOLD, "CRL_REASON_CERTIFICATE_HOLD");
            }
            _logger.Log($"No match found for revocation reason {reason:G}");
            return (int.MaxValue, "");
        }

        public override Task<GetTemplatesReply> GetTemplates(GetTemplatesRequest request, ServerCallContext context)
        {
            _logger.Log("GetTemplates");
            var reply = new GetTemplatesReply
            {
                Status = new()
            };

            IEnumerable<CertificateTemplate> templateList;
            try
            {
                templateList = _ldapOp.GetCertificateTemplates();
            }
            catch (Exception ex)
            {
                _logger.Error($"GetCertificateTemplates encountered an error:\n{ex.Message}\n{ex.StackTrace}");
                reply.Status.Code = 1;
                reply.Status.Message = ex.Message;
                return Task.FromResult(reply);
            }

            if (templateList is not null)
            {
                reply.TemplateNames.AddRange(templateList.Select(template => template.Name));
            }

            _logger.Log($"Replying with template name list: {string.Join(", ", reply.TemplateNames)}");
            return Task.FromResult(reply);
        }

        public override Task<GetCAsReply> GetCAs(GetCAsRequest request, ServerCallContext context)
        {
            _logger.Log("GetCAs");
            var reply = new GetCAsReply
            {
                Status = new()
            };

            IEnumerable<EnterpriseCertificateAuthority> caList;
            try
            {
                caList = _ldapOp.GetEnterpriseCAs();
            }
            catch (Exception ex)
            {
                _logger.Error($"GetEnterpriseCAs encountered an error:\n{ex.Message}\n{ex.StackTrace}");
                reply.Status.Code = 1;
                reply.Status.Message = ex.Message;
                return Task.FromResult(reply);
            }

            if (caList is not null)
            {
                reply.CaNames.AddRange(caList.Select(ca => ca.FullName));
            }

            _logger.Log($"Replying with CA list: {string.Join(", ", reply.CaNames)}");
            return Task.FromResult(reply);
        }

        public override Task<GetCertificateReply> GetCertificate(GetCertificateRequest request, ServerCallContext context)
        {
            _logger.Log($"GetCertificate for id {request.Id} from CA {request.CaName}");
            int id = request.Id;
            var reply = new GetCertificateReply
            {
                Status = new(),
                Cert = ""
            };

            if (request.Id == 0 || string.IsNullOrEmpty(request.CaName))
            {
                _logger.Log("Invalid Parameter. RequestId = 0 or CA Name empty!");
                reply.Status.Code = 1;
                reply.Status.Message = "Invalid Parameter. RequestId = 0 or CA Name empty!";
                return Task.FromResult(reply);
            }

            string? cert;
            try
            {
                cert = _certOps.DownloadCert(request.CaName, id);
            }
            catch (COMException comex)
            {
                _logger.Error($"DownloadCert encountered a COMException:\n{comex.Message}, Code: {comex.ErrorCode}\n{comex.StackTrace}");
                reply.Status.Code = comex.ErrorCode;
                reply.Status.Message = comex.Message;
                return Task.FromResult(reply);
            }
            catch (Exception ex)
            {
                _logger.Error($"DownloadCert encountered an error:\n{ex.Message}\n{ex.StackTrace}");
                reply.Status.Code = 1;
                reply.Status.Message = ex.Message;
                return Task.FromResult(reply);
            }

            if (cert != null)
            {
                reply.Cert = cert;
            }
            else
            {
                _logger.Log("Retrieved an empty response from the CA.");
            }

            return Task.FromResult(reply);
        }

        public override Task<GetCSRStatusReply> GetCSRStatus(GetCSRStatusRequest request, ServerCallContext context)
        {
            _logger.Log($"GetCRStatus for ID {request.CertRequestId} from CA {request.CaName}");
            var reply = new GetCSRStatusReply
            {
                Status = new()
            };
            if (string.IsNullOrEmpty(request.CaName) || request.CertRequestId == 0)
            {
                reply.Status.Code = 1;
                reply.Status.Message = "CA Name empty or CertRequestId is 0";
                return Task.FromResult(reply);
            }
            try
            {
                reply.Disposition = _certOps.GetRequestStatus(request.CertRequestId, null, request.CaName);
            }
            catch (COMException comex)
            {
                _logger.Error($"GetRequestStatus encountered a COMException:\n{comex.Message}, Code: {comex.ErrorCode}\n{comex.StackTrace}");
                reply.Status.Code = comex.ErrorCode;
                reply.Status.Message = comex.Message;
                return Task.FromResult(reply);
            }
            catch (Exception ex)
            {
                _logger.Error($"GetRequestStatus encountered an error:\n{ex.Message}\n{ex.StackTrace}");
                reply.Status.Code = 1;
                reply.Status.Message = ex.Message;
                return Task.FromResult(reply);
            }

            reply.DispositionMessage = _certOps.GetDispositionMessage() ?? "";
            _logger.Log($"Returning dispositon {reply.Disposition}");
            return Task.FromResult(reply);
        }

        public override Task<SubmitCSRReply> SubmitCSR(SubmitCSRRequest request, ServerCallContext context)
        {
            _logger.Log($"Submitting CR to {request.CaName} for template {request.TemplateName}. CR:\n{request.Csr}");
            var reply = new SubmitCSRReply
            {
                Status = new()
            };

            if (string.IsNullOrEmpty(request.TemplateName))
            {
                _logger.Log("TemplateName is empty!");
                reply.Status.Code = 1;
                reply.Status.Message = "TemplateName is empty!";
                return Task.FromResult(reply);
            }

            if (string.IsNullOrEmpty(request.Csr))
            {
                _logger.Log("CertificateRequest is empty!");
                reply.Status.Code = 1;
                reply.Status.Message = "CertificateRequest is empty!";
                return Task.FromResult(reply);
            }

            if (string.IsNullOrEmpty(request.CaName))
            {
                _logger.Log("CA Name is empty!");
                reply.Status.Code = 1;
                reply.Status.Message = "CA Name is empty!";
                return Task.FromResult(reply);
            }

            CertSubmissionResult ret;
            try
            {
                ret = _certOps.SendCertificateRequest(request.CaName, request.Csr, templateName: request.TemplateName);
            }
            catch (COMException comex)
            {
                _logger.Error($"SendCertificateRequest encountered a COMException:\n{comex.Message}, Code: {comex.ErrorCode}\n{comex.StackTrace}");
                _logger.Error($"Error code:{comex.ErrorCode}, error message: {comex.Message}");
                reply.Status.Code = comex.ErrorCode;
                reply.Status.Message = comex.Message;
                return Task.FromResult(reply);
            }
            catch (Exception ex)
            {
                _logger.Error($"SendCertificateRequest encountered an error:\n{ex.Message}\n{ex.StackTrace}");
                reply.Status.Code = 1;
                reply.Status.Message = ex.Message;
                return Task.FromResult(reply);
            }

            reply.RequestId = ret.RequestId;
            reply.Disposition = ret.Disposition;
            reply.DispositionMessage = ret.DispositionMessage;
            reply.Status.Code = 0;
            reply.Status.Message = "";
            return Task.FromResult(reply);
        }

        public override Task<SetOptionReply> SetOption(SetOptionRequest request, ServerCallContext context)
        {
            SetOptionReply reply = new()
            {
                Status = new()
            };
            if (!string.IsNullOrEmpty(request.OptionName))
            {
                if (options.TryGetValue(request.OptionName, out string? value))
                {
                    _logger.Log($"Overwriting Option {request.OptionName}={value} with new value {request.OptionValue}");
                }

                options.Add(request.OptionName, request.OptionValue);
                reply.Status.Code = 0;
                reply.Status.Message = "";
            }
            else
            {
                reply.Status.Code = 1;
                reply.Status.Message = "OptionName cannot be empty";
            }

            return Task.FromResult(reply);
        }

        public override Task<GetOptionsReply> GetOptions(GetOptionsRequest request, ServerCallContext context)
        {
            GetOptionsReply reply = new()
            {
                Status = new()
                {
                    Code = 0,
                    Message = ""
                }
            };

            foreach (var pair in options)
            {
                if (!string.IsNullOrEmpty(pair.Key))
                {
                    reply.Options.Add(pair.Key, pair.Value);
                }
                else
                {
                    _logger.Log($"Empty option name with value {pair.Value} will be skipped");
                }
            }

            return Task.FromResult(reply);
        }
    }
}
