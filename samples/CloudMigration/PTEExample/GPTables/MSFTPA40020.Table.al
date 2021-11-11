table 50545 MSFTPA40020 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; PAALLOCATIONDESCRIPTION; Text[101])
        {
            DataClassification = CustomerContent;
        }
        field(2; PAALLOCATIONID; Text[15])
        {
            DataClassification = CustomerContent;
        }
        field(3; PAActive; Integer)
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
        key(Key1; PAALLOCATIONID)
        {
            Clustered = true;
        }
    }
}

