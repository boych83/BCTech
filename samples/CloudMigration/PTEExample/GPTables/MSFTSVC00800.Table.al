table 50963 MSFTSVC00800 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; Keyword; Text[21])
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
        key(Key1; Keyword)
        {
            Clustered = true;
        }
    }
}

