from data_loader import load_flow_data

def detect_attacks(df):
    df = df.copy()
    
    # Rule 1: Port scan - very short flow duration, minimal packets, SYN present
    df['Suspected_PortScan'] = (
        (df['Flow Duration'] < 200) & 
        (df['Total Fwd Packet'] <= 2) &
        (df['SYN Flag Count'] >= 1)
    )
    
    # Rule 2: DDoS - long sustained flow duration with meaningful data volume
    df['Suspected_DDoS'] = (
        (df['Flow Duration'] > 1000000) &
        (df['Total Fwd Packet'] > 3)
    )
    
    df['Is_Suspicious'] = df['Suspected_PortScan'] | df['Suspected_DDoS']
    
    return df

if __name__ == "__main__":
    df = load_flow_data(r"D:\network-forensics\friday.csv")
    df = detect_attacks(df)
    
    print("Total flagged as suspicious:", df['Is_Suspicious'].sum())
    print("\nHow well does this match the real Label?")
    print(df.groupby(['Label', 'Is_Suspicious']).size())