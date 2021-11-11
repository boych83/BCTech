table 51037 MSFTSVC06002 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; DEPSTATGRP; Text[11])
        {
            DataClassification = CustomerContent;
        }
        field(2; STATIONID; Text[11])
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
        key(Key1; DEPSTATGRP,STATIONID)
        {
            Clustered = true;
        }
    }
}

