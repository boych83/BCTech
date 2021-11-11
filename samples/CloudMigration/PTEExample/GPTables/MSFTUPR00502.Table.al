table 51209 MSFTUPR00502 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; EMPLOYID; Text[15])
        {
            DataClassification = CustomerContent;
        }
        field(2; DEDUCTON; Text[7])
        {
            DataClassification = CustomerContent;
        }
        field(3; DEDNSQNC; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(4; SPLITMTHD; Integer)
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
        key(Key1; EMPLOYID,DEDUCTON)
        {
            Clustered = true;
        }
    }
}

