table 50577 MSFTPA42602 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; PABill_Format_Key; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(2; USERID; Text[15])
        {
            DataClassification = CustomerContent;
        }
        field(3; DEX_ROW_ID; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(4; PRNSET; Text[2048])
        {
            DataClassification = CustomerContent;
        }
    }
    keys
    {
        key(Key1; PABill_Format_Key,USERID)
        {
            Clustered = true;
        }
    }
}

