table 51133 MSFTSY01401 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; USERID; Text[15])
        {
            DataClassification = CustomerContent;
        }
        field(2; coDefaultType; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(3; USRDFSTR; Text[255])
        {
            DataClassification = CustomerContent;
        }
        field(4; DEX_ROW_ID; Integer)
        {
            DataClassification = CustomerContent;
        }
    }
    keys
    {
        key(Key1; USERID,coDefaultType)
        {
            Clustered = true;
        }
    }
}

