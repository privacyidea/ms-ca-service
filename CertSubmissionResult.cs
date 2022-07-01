namespace CAService
{
    public record CertSubmissionResult
    {
        public int Disposition;
        public string DispositionMessage;
        public int RequestId;
        public uint LastStatus;

        public CertSubmissionResult(int disposition, string dispositionMessage, int requestId, uint lastStatus)
        {
            Disposition = disposition;
            DispositionMessage = dispositionMessage;
            RequestId = requestId;
            LastStatus = lastStatus;
        }
    }
}
