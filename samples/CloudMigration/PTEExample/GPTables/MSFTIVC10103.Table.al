table 50297 MSFTIVC10103 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; DOCTYPE; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(2; INVCNMBR; Text[21])
        {
            DataClassification = CustomerContent;
        }
        field(3; LNITMSEQ; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(4; COMMENT_1; Text[51])
        {
            DataClassification = CustomerContent;
        }
        field(5; COMMENT_2; Text[51])
        {
            DataClassification = CustomerContent;
        }
        field(6; COMMENT_3; Text[51])
        {
            DataClassification = CustomerContent;
        }
        field(7; COMMENT_4; Text[51])
        {
            DataClassification = CustomerContent;
        }
        field(8; DEX_ROW_ID; Integer)
        {
            DataClassification = CustomerContent;
        }
        field(9; CMMTTEXT; Text[2048])
        {
            DataClassification = CustomerContent;
        }
    }
    keys
    {
        key(Key1; DOCTYPE,INVCNMBR,LNITMSEQ)
        {
            Clustered = true;
        }
    }
}

