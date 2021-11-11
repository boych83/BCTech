table 50401 MSFTPA02010 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; PABILLCYCLEID1; Text[15])
        {
            DataClassification = CustomerContent;
        }
        field(2; PABILLCYCLEDESC1; Text[41])
        {
            DataClassification = CustomerContent;
        }
        field(3; NOTEINDX; Decimal)
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
        key(Key1; PABILLCYCLEID1)
        {
            Clustered = true;
        }
    }
}

