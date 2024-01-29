import streamlit as st
from streamlit_option_menu import option_menu
import base64
import pickle
import pandas as pd
from sklearn.preprocessing import StandardScaler,LabelEncoder
import seaborn as sns
import matplotlib.pyplot as plt
import random



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


prevention_software_list = [
    "Digital Guardian",
    "Forcepoint",
    "Broadcom Data Loss Prevention",
    "Endpoint Protector",
    "McAfee",
    "Check Point Data Loss Prevention",
    "Code42",
    "GTB Technologies",
    "Proofpoint",
    "Teramind",
    "Trellix",
    "Spirion",
    "Trellix Data Loss Prevention",
    "Trend Micro",
    "Zscaler"
]

style_home="""<style>
            h2{
                color:#004f7f;
                font-size:100px;
                font-family:Alata;
                margin-left:150px;
                gap:10px;
            
            }

             h3{
                color:red;
                font-size:50px;
                font-family:Alata;
                margin-left:100px;
                gap:10px;
            
            }

            h5{
                color:#004f7f;
                font-size:30px;
                font-family:Alata;
                margin-left:100px;
                gap:10px;
            
            }

            p{
                color:grey;
                font-size:20px;
                margin-left:10px;
                margin-right:10px;
            }
</style>"""

def generate_team_card(name, roll_number, designation):
    card_html = f"""
        <div style="border: 1px solid #ddd; padding: 10px; margin:5px; width: 230px;">
            <h4>{name}</h4>
            <p>Roll Number: {roll_number}</p>
            <p>Designation: {designation}</p>
        </div>
    """
    return card_html





c1,c2,c3=st.columns(3)
c2.image('logo.png',use_column_width=True)
st.markdown(style_home,unsafe_allow_html=True)
st.markdown('''<h5>Detection and Preventions of Attack</h5>''',unsafe_allow_html=True)

selected=option_menu(
    menu_title=None,
    options=['home','application','team'],
    icons=['house','code-slash','people-fill'],
    default_index=0,
    orientation='horizontal',
    styles={
        "container": {"padding": "0!important", "background-color": "#faf22"},
        "icon": {"color": "orange", "font-size": "25px"}, 
        "nav-link": {"font-size": "25px", "text-align": "left", "margin":"0px", "--hover-color": "#eee"},
        "nav-link-selected": {"background-color": "green"},
    }
    )


if selected=='home':
    st.markdown(style_home,unsafe_allow_html=True)
    st.markdown('--------------')
    st.markdown('''<h1>Summary</h1>''',unsafe_allow_html=True)
    st.markdown('''<p>
                    Lorem ipsum dolor sit amet, consectetur adipiscing elit.
                    Nullam in tincidunt dolor.
                    Quisque vel felis vel nisl malesuada eleifend.
                    Maecenas at elit vel nulla commodo commodo vel ac lacus.
                    Vivamus ultrices, quam ut tristique aliquet, neque nisl hendrerit elit, id hendrerit enim tortor nec urna.
                    Sed euismod tortor at bibendum imperdiet.
                    Fusce efficitur tellus et leo imperdiet, a pellentesque odio dictum.
                    Ut at feugiat lectus.
                    Integer ut commodo urna.
                    In hac habitasse platea dictumst.
                    Curabitur auctor efficitur libero, id hendrerit felis hendrerit vel.
                    Suspendisse potenti.
                    Duis ut lectus vel odio fermentum ultricies.
                    Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas.
                    Proin commodo, quam non bibendum fermentum, arcu dolor vehicula sapien, vel luctus turpis urna eu ligula.
                </p>''',unsafe_allow_html=True)
    st.markdown('------------')
    st.markdown('''<h1>Graphical Representation</h1>''',unsafe_allow_html=True)
    st.image('./result.png',use_column_width=True)
    st.markdown('------------')





if selected=='application':

    file=st.file_uploader("",type=['csv','txt'])
    if file is not None:
        print(file.name[-3:])

        if file.name[-3:]=='csv':
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


                st.markdown(style_home,unsafe_allow_html=True)
                st.markdown('<h2>Detections</h2>',unsafe_allow_html=True)
                st.dataframe(test_df_copy.head())


                anomaly_val=len(test_df_copy[test_df_copy['predicted_label']=='Anomly'])
                normal_val=len(test_df_copy[test_df_copy['predicted_label']=='Normal'])

                # print("anomaly{}\nnormal:{}".format(anomaly_val,normal_val))
                if anomaly_val > normal_val:
                    st.markdown(style_home,unsafe_allow_html=True)
                    st.markdown("<h3>Anomaly in the CSV File!</h3>",unsafe_allow_html=True)

                    # Choose three random values from the list
                    random_values = random.sample(prevention_software_list, 3)


                    # Create a pie chart
                    plt.figure(figsize=(8, 8))
                    plt.pie([anomaly_val,normal_val], labels=['anomaly','normal'], autopct='%1.1f%%', startangle=90, colors=sns.color_palette('pastel'))
                    plt.title('Total Anomalies and Normal Entries in CSV files')
                    plt.savefig('result.png')
                    # plt.show()


                    # Print the result
                    print("Three random values from the list:", random_values)
                    st.warning(f'recommended Softwares{random_values}')

                else:
                    st.markdown(style_home,unsafe_allow_html=True)
                    st.markdown("<h4>No Instursion Detected!</h4>",unsafe_allow_html=True)    
            else:
                st.warning('Please Upload CSV Files!')

        if file.name[-3:]=='txt':
            if file is not None:

                test_df=pd.read_csv(file,sep="\t")
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

                st.markdown(style_home,unsafe_allow_html=True)
                st.markdown('<h2>Detections!</h2>',unsafe_allow_html=True)
                st.dataframe(test_df_copy.head())


                anomaly_val=len(test_df_copy[test_df_copy['predicted_label']=='Anomly'])
                normal_val=len(test_df_copy[test_df_copy['predicted_label']=='Normal'])

                print("anomaly{}\nnormal:{}".format(anomaly_val,normal_val))
                if anomaly_val > normal_val:
                    st.markdown(style_home,unsafe_allow_html=True)
                    st.markdown("<h3>Anomaly in the Text File!</h3>",unsafe_allow_html=True)
                    
                    # Choose three random values from the list
                    random_values = random.sample(prevention_software_list, 3)

                    # Print the result
                    print("Three random values from the list:", random_values)
                    st.warning(f'recommended Softwares{random_values}')



                    
                    # Create a pie chart
                    plt.figure(figsize=(8, 8))
                    plt.pie([anomaly_val,normal_val], labels=['anomaly','normal'], autopct='%1.1f%%', startangle=90, colors=sns.color_palette('pastel'))
                    plt.title('Total Anomalies and Normal Entries in Txt files')
                    plt.savefig('result.png')
                    # plt.show()
                
                else:    
                    st.markdown(style_home,unsafe_allow_html=True)
                    st.markdown("<h4>No Instursion Detected!</h4>",unsafe_allow_html=True)

            
            else:
                st.warning('Please Upload CSV Files!')
    else:
        st.warning('Please Upload CSV OR TXT Files!')



if selected=='team':
        
    team_data = [
        {"name": "John Doe", "roll_number": "12345", "designation": "Software Engineer"},
        {"name": "Jane Smith", "roll_number": "67890", "designation": "Data Scientist"},
        {"name": "Bob Johnson", "roll_number": "54321", "designation": "Product Manager"},
        {"name": "Alice Brown", "roll_number": "98765", "designation": "UI/UX Designer"},
        {"name": "Charlie Davis", "roll_number": "45678", "designation": "Marketing Specialist"},
        # {"name": "Eva White", "roll_number": "87654", "designation": "Project Manager"},
    ]

    # Display team cards in rows of three
    st.title("Team Information")

    for i in range(0, len(team_data), 3):
        row_data = team_data[i:i+2]
        
        # Split the row into columns
        columns = st.columns(len(row_data))
        
        for column, member in zip(columns, row_data):
            column.markdown(generate_team_card(**member), unsafe_allow_html=True)