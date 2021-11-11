table 50854 MSFTSOP40101 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; SOPSTATUS; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(2; SOPSTSDESCR; Text[51])
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
        key(Key1; SOPSTATUS)
        {
            Clustered = true;
        }
    }
}

