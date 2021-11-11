table 50820 MSFTSE465546 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; SEOPTNME; Text[21])
        {
            DataClassification = CustomerContent;
        }
        field(2; SE_Column_Number; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(3; SE_Token_Position; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(4; SE_Token; Text[11])
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
        key(Key1; SEOPTNME,SE_Column_Number,SE_Token_Position)
        {
            Clustered = true;
        }
    }
}

