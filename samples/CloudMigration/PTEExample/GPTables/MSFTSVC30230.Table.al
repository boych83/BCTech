table 51077 MSFTSVC30230 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; SRVRECTYPE; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(2; CALLNBR; Text[11])
        {
            DataClassification = CustomerContent;
        }
        field(3; SEQNUMBR; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(4; SVC_Distribution_Type; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(5; DistRef; Text[31])
        {
            DataClassification = CustomerContent;
        }
        field(6; ACTINDX; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(7; DEBITAMT; Decimal)
        {
            DataClassification = CustomerContent;
        }
        field(8; ORDBTAMT; Decimal)
        {
            DataClassification = CustomerContent;
        }
        field(9; CRDTAMNT; Decimal)
        {
            DataClassification = CustomerContent;
        }
        field(10; ORCRDAMT; Decimal)
        {
            DataClassification = CustomerContent;
        }
        field(11; CURRNIDX; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(12; TRXSORCE; Text[13])
        {
            DataClassification = CustomerContent;
        }
        field(13; POSTED; Boolean)
        {
            DataClassification = CustomerContent;
        }
        field(14; POSTEDDT; DateTime)
        {
            DataClassification = CustomerContent;
        }
        field(15; DEX_ROW_ID; Integer)
        {
            DataClassification = CustomerContent;
        }
    }
    keys
    {
        key(Key1; SRVRECTYPE,CALLNBR,SEQNUMBR,SVC_Distribution_Type)
        {
            Clustered = true;
        }
    }
}

