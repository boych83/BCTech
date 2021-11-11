table 51062 MSFTSVC07000 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; Menu_ID; Decimal)
        {
            DataClassification = CustomerContent;
        }
        field(2; Name; Text[31])
        {
            DataClassification = CustomerContent;
        }
        field(3; KeyCode; Text[11])
        {
            DataClassification = CustomerContent;
        }
        field(4; Path; Text[255])
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
        key(Key1; Menu_ID)
        {
            Clustered = true;
        }
    }
}

