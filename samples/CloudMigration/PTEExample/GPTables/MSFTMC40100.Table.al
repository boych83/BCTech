table 50332 MSFTMC40100 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; RATETPID; Text[15])
        {
            DataClassification = CustomerContent;
        }
        field(2; DEX_ROW_ID; Integer)
        {
            DataClassification = CustomerContent;
        }
    }
    keys
    {
        key(Key1; RATETPID)
        {
            Clustered = true;
        }
    }
}

