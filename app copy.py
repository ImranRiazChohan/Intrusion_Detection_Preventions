import streamlit as st
import pickle
import pandas as pd
from sklearn.preprocessing import StandardScaler,LabelEncoder
import base64



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



def get_base64(bin_file):
    with open(bin_file, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode()


def set_background(png_file):
    bin_str = get_base64(png_file)
    page_bg_img = '''
    <style>
    .stApp {
    background-image: url("data:image/png;base64,%s");
    background-size: cover;
    }
    </style>
    ''' % bin_str
    st.markdown(page_bg_img, unsafe_allow_html=True)


style="""<style>
            h1{
                color:#004f7f;
                font-size:30px;
                font-family:Alata;
                margin-left: 50px;
            
            }
</style>"""

set_background('./background.png')
st.image('./logo.png',width=300, use_column_width=True)
st.markdown(style,unsafe_allow_html=True)
st.markdown(f'<h1>DETECTION & PREVENTION OF ATTACKS</h1>',unsafe_allow_html=True)


c1,c2,c3,c4,c5=st.columns(5)
if c3.button('Get Started',use_container_width=True):

    formats=st.radio('',["Upload csv","Upload txt"])


if formats=="Upload csv":

    file=st.file_uploader("",type='csv')


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


elif formats=='Upload txt':
    file1=st.file_uploader("",type='txt')

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


        st.header('Final Results')
        st.dataframe(test_df_copy.head())


        anomaly_val=len(test_df_copy[test_df_copy['predicted_label']=='Anomly'])
        normal_val=len(test_df_copy[test_df_copy['predicted_label']=='Normal'])

        print("anomaly{}\nnormal:{}".format(anomaly_val,normal_val))
        if anomaly_val > normal_val:
            st.title("Anomaly in the Text File :red[red]")
        else:
            st.markdown("No Instursion Detected :white[white]")    

    else:
        st.warning('Please Upload CSV Files!')

