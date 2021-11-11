table 50976 MSFTSVC00909 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; SVCAREA; Text[11])
        {
            DataClassification = CustomerContent;
        }
        field(2; NAME; Text[31])
        {
            DataClassification = CustomerContent;
        }
        field(3; DEX_ROW_ID; Integer)
        {
            DataClassification = CustomerContent;
        }
    }
    keys
    {
        key(Key1; SVCAREA)
        {
            Clustered = true;
        }
    }
}

