table 51375 MSFTWorkflowTrackingHistory 
{
    DataClassification = CustomerContent;
    fields
    {
        field(1; WorkflowID; Text[255])
        {
            DataClassification = CustomerContent;
        }
        field(2; GPWorkflowID; Text[255])
        {
            DataClassification = CustomerContent;
        }
        field(3; BusinessObjKey; Text[255])
        {
            DataClassification = CustomerContent;
        }
        field(4; WorkflowTrackingHistory; Text[2048])
        {
            DataClassification = CustomerContent;
        }
    }
    keys
    {
        key(Key1; WorkflowID,GPWorkflowID,BusinessObjKey)
        {
            Clustered = true;
        }
    }
}

