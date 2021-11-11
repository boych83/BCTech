table 50877 MSFTSOP50700 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; FIELD12; Text[133])
        {
            DataClassification = CustomerContent;
        }
        field(2; SEQNUMBR; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(3; USERID; Text[15])
        {
            DataClassification = CustomerContent;
        }
        field(4; Process_ID; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(5; DEX_ROW_ID; Integer)
        {
            DataClassification = CustomerContent;
        }
    }
    keys
    {
        key(Key1; USERID,Process_ID,SEQNUMBR)
        {
            Clustered = true;
        }
    }
}

