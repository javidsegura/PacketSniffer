import streamlit as st
from memoryListener import startDefense

def main():

      st.title("Demo App")

      st.write("This is a demo app for the stress test")

      startDefense()


main()