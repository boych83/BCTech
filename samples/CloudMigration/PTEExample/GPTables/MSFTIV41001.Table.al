table 50285 MSFTIV41001 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; EXCEPTIONDATE; DateTime)
        {
            DataClassification = CustomerContent;
        }
        field(2; DATETYPE; Integer)
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
        key(Key1; EXCEPTIONDATE)
        {
            Clustered = true;
        }
    }
}

