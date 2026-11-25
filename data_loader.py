import pandas as pd

def load_flow_data(filepath):
    """Load and clean CIC-IDS-2017 style flow CSV."""
    df = pd.read_csv(filepath)
    
    # Strip any stray whitespace from column names
    df.columns = df.columns.str.strip()
    
    # Keep only the columns relevant to forensic timeline/detection
    relevant_cols = [
        'Src IP dec', 'Src Port', 'Dst IP dec', 'Dst Port',
        'Protocol', 'Timestamp', 'Flow Duration',
        'Total Fwd Packet', 'Total Bwd packets',
        'SYN Flag Count', 'RST Flag Count', 'ACK Flag Count',
        'Label'
    ]
    df = df[relevant_cols]
    
    # Timestamp is damaged (missing date/hour) - use row order as sequence proxy
    df = df.reset_index().rename(columns={'index': 'Event_Order'})
    
    return df

if __name__ == "__main__":
    df = load_flow_data(r"D:\network-forensics\friday.csv")
    print("Loaded shape:", df.shape)
    print(df.head())
    print("\nEvent_Order range:", df['Event_Order'].min(), "to", df['Event_Order'].max())