from data_loader import load_flow_data
from attack_detection import detect_attacks

def build_timeline(df):
    """Reconstruct chronological attack sequence from suspicious flows."""
    df = df.copy()
    
    # Keep only suspicious events for the timeline
    suspicious = df[df['Is_Suspicious']].copy()
    
    # Sort by Event_Order (our proxy for time, since real timestamps are damaged)
    suspicious = suspicious.sort_values('Event_Order')
    
    # Assign an attack type label based on which rule triggered
    def classify(row):
        if row['Suspected_PortScan'] and row['Suspected_DDoS']:
            return 'PortScan+DDoS'
        elif row['Suspected_PortScan']:
            return 'PortScan'
        elif row['Suspected_DDoS']:
            return 'DDoS'
        return 'Unknown'
    
    suspicious['Attack_Type'] = suspicious.apply(classify, axis=1)
    
    # Build a simplified timeline view
    timeline = suspicious[['Event_Order', 'Src IP dec', 'Dst IP dec', 
                            'Dst Port', 'Attack_Type', 'Label']]
    
    return timeline

if __name__ == "__main__":
    df = load_flow_data(r"D:\network-forensics\friday.csv")
    df = detect_attacks(df)
    timeline = build_timeline(df)
    
    print("Total events in timeline:", len(timeline))
    print("\nFirst 10 events in the reconstructed attack timeline:")
    print(timeline.head(10))
    print("\nAttack type breakdown:")
    print(timeline['Attack_Type'].value_counts())
    
    # Save timeline to CSV for later use (dashboard/report)
    timeline.to_csv(r"D:\network-forensics\attack_timeline.csv", index=False)
    print("\nSaved to attack_timeline.csv")