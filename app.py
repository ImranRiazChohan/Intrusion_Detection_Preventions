import streamlit as st
import pickle
import pandas as pd
from sklearn.preprocessing import StandardScaler,LabelEncoder
import base64
import seaborn as sns
import matplotlib.pyplot as plt


def label_encoder(df):
    for col in df.columns:
        if df[col].dtype == 'object':
                label_encoder = LabelEncoder()
                df[col] = label_encoder.fit_transform(df[col])
    return df



def download_csv(data):
    csv_file = data.to_csv(index=False)
    b64 = base64.b64encode(csv_file.encode()).decode()
    href = f'<a href="data:file/csv;base64,{b64}" download="data.csv">Download CSV File</a>'
    return href


# def map_ranges_to_labels(probability):
#     for (lower, upper), label in ranges_labels.items():
#         if lower <= probability <= upper:
#             return label
#     return 'Other'

st.header('Network Intrusion Detection and Prevention System')

formats=st.sidebar.radio('Which to file you have to Upload',["comma seperated files(CSV)","text files(TXT)"])

if formats=="comma seperated files(CSV)":

    file=st.sidebar.file_uploader("Uplad CSV file",type='csv')


    if file is not None:

        test_df=pd.read_csv(file)
        test_df_copy=test_df.copy()

        selected_features=['protocol_type',
        'flag',
        'src_bytes',
        'dst_bytes',
        'count',
        'same_srv_rate',
        'diff_srv_rate',
        'dst_host_srv_count',
        'dst_host_same_srv_rate',
        'dst_host_same_src_port_rate']
        
        test_df=test_df[selected_features]
        
        st.dataframe(test_df_copy.head())

        encoded_df=label_encoder(test_df)
    

        scale=StandardScaler()
        test = scale.fit_transform(encoded_df)
        

        model=pickle.load(open('./random_forest_model.sav', 'rb'))
        predict=model.predict(test)
        predict_prob=model.predict_proba(test)
    
        test_df_copy['predicted_label']=predict
        
        test_df_copy['anomly_prediction_prob']=predict_prob[:,1]
        # test_df_copy['normal_prediction_prob']=predict_prob[:,0]
        
        test_df_copy['predicted_label']=test_df_copy['predicted_label'].replace({0:'Normal',1:'Anomly'})
        

        prob_val=test_df_copy['anomly_prediction_prob']

        # ranges_labels = {
        # (0.2, 0.3): 'Delete Files',
        # (0.4, 0.5): 'Clean C Drive',
        # (0.5, 0.6): 'Install Antivirus',
        # (0.6, 0.7): 'Apply FireWalls',
        # (0.7, 0.8): 'Network Security',
        # (0.8, 0.9): 'Ip Whitelisting',
        # (0.9, 0.100): 'Internal Audit',
        # }
        # test_df_copy['Recommendations'] = test_df_copy['anomly_prediction_prob'].apply(map_ranges_to_labels)

        st.header('Final Results')
        st.dataframe(test_df_copy.head())

        # # Download button for selected data as CSV
        # st.markdown(download_csv(test_df_copy), unsafe_allow_html=True)

        anomaly_val=len(test_df_copy[test_df_copy['predicted_label']=='Anomly'])
        normal_val=len(test_df_copy[test_df_copy['predicted_label']=='Normal'])

        # print("anomaly{}\nnormal:{}".format(anomaly_val,normal_val))
        if anomaly_val > normal_val:
            st.title("Anomaly in the CSV File")
        else:
            st.title("No Instursion Detected")    
    else:
        st.warning('Please Upload CSV Files!')


elif formats=='text files(TXT)':
    file1=st.sidebar.file_uploader("Uplad Text file",type='txt')

    if file1 is not None:

        test_df=pd.read_csv(file1,sep="\t")
        test_df_copy=test_df.copy()

        selected_features=['protocol_type',
        'flag',
        'src_bytes',
        'dst_bytes',
        'count',
        'same_srv_rate',
        'diff_srv_rate',
        'dst_host_srv_count',
        'dst_host_same_srv_rate',
        'dst_host_same_src_port_rate']
        
        test_df=test_df[selected_features]
        
        st.dataframe(test_df_copy.head())

        encoded_df=label_encoder(test_df)
    

        scale=StandardScaler()
        test = scale.fit_transform(encoded_df)
        

        model=pickle.load(open('./random_forest_model.sav', 'rb'))
        predict=model.predict(test)
        predict_prob=model.predict_proba(test)
    
        test_df_copy['predicted_label']=predict
        
        test_df_copy['anomly_prediction_prob']=predict_prob[:,1]
        # test_df_copy['normal_prediction_prob']=predict_prob[:,0]
        
        test_df_copy['predicted_label']=test_df_copy['predicted_label'].replace({0:'Normal',1:'Anomly'})
        

        prob_val=test_df_copy['anomly_prediction_prob']



# Prevention software
# 1. Digital guardian
# 2. Forcepoint
# 3. Broadcom data loss prevention
# 4. Endpoint protector
# 5. McAfee
# 6. Check Point data loss prevention
# 7. Code42
# 8. GTB Technologies
# 9. Proofpoint
# 10. Teramind
# 11. Trellix
# 12. Spirion
# 13. Trellix data loss prevention
# 14. Trend micro
# 15. Zscaler logo

        st.header('Final Results')
        st.dataframe(test_df_copy.head())

        # # # Download button for selected data as CSV
        # st.markdown(download_csv(test_df_copy), unsafe_allow_html=True)


        anomaly_val=len(test_df_copy[test_df_copy['predicted_label']=='Anomly'])
        normal_val=len(test_df_copy[test_df_copy['predicted_label']=='Normal'])

        print("anomaly{}\nnormal:{}".format(anomaly_val,normal_val))
        if anomaly_val > normal_val:
            st.title("Anomaly in the Text File")
        else:
            st.title("No Instursion Detected")    

    else:
        st.warning('Please Upload CSV Files!')



