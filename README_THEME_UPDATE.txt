NETRA THEME UPDATE

This patch changes only the visual theme, chart presentation, and login-page layout.
It does not change the detection rules, data input modes, ML logic, alert logic, or firewall implementation.

Apply it safely:
1. Keep a backup copy of your current IPS-IDS-main folder.
2. Extract this ZIP directly INTO your existing IPS-IDS-main folder.
3. Allow Windows to overwrite app.py and services/auth.py.
4. The .streamlit/config.toml file will be added as a new folder/file.
5. Do not delete or replace your .venv folder.
6. Run the project as usual: python -m streamlit run app.py

Colour palette:
#190019  #2B124C  #522B5B  #854F6C  #DFB6B2  #FBE4D8

Default demo credentials remain:
Admin: admin / admin123
Viewer: viewer / viewer123
