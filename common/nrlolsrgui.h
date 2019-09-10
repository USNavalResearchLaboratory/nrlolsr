#include "../protolib/include/wxProtoApp.h"

#include "wx/choicebk.h"

#include "wx/listbox.h"

#include "wx/gbsizer.h"



#define PIPE_TYPE ProtoPipe::MESSAGE



class OLSRApp;



class MyFrame : public wxFrame
{

public:

    MyFrame(const wxString& title, const wxPoint& pos = wxDefaultPosition,

        const wxSize& size = wxDefaultSize,

		long style = wxDEFAULT_FRAME_STYLE|wxCLIP_CHILDREN|wxNO_FULL_REPAINT_ON_RESIZE);

	~MyFrame();

	void SetApp(OLSRApp* handle);



	void ClearDestEntries();

	void AddDestEntry(const char* dest ,const char* gw, const char* weight,const char* interfacename);

	void DisplayDestEntries();



	void ClearNeighborEntries();

	void AddNeighborEntry(const char* neighbor,const char* type,const char* hysterisis, const char* MPRselect);

	void DisplayNeighborEntries();

	void SetSettings(const char* al, const char* fuzzy, const char* slowdown, 

			 const char* hi, const char* hj, const char* ht,

			 const char* tci, const char* tcj, const char* tct,

			 const char* hnai, const char* hnaj, const char* hnat,

			 const char* up, const char* down, const char* alpha,
			 
			 const char* willingness);



 private:

        OLSRApp* theApp;

	void RecreateBooks();

    	void OnListbox_dest(wxCommandEvent& event);

	void OnListbox_neighbor(wxCommandEvent& event);

	void OnRefreshButton_dest(wxCommandEvent& event);

	void OnRefreshButton_neighbor(wxCommandEvent& event);

	void CreateInitialPages(wxBookCtrlBase *parent);

	void OnSetSettings(wxCommandEvent& event); //button event

	void OnGetSettings(wxCommandEvent& event); //button event



	void OnSettingsEditOne(wxCommandEvent& event); //settings in panel one were changed event



	wxPanel *CreateRoutesPage(wxBookCtrlBase *parent);

	wxPanel *CreateNeighborInfoPage(wxBookCtrlBase *parent);

	wxPanel *CreateDebugPage(wxBookCtrlBase *parent);

	wxPanel *CreateSettingsPage(wxBookCtrlBase *parent);

	wxPanel *CreatePage(wxBookCtrlBase *parent, const wxString&pageName);



    	wxPanel      * m_panel;

    	wxNotebook   * m_notebook;

	wxChoicebook * m_choicebook;

    	wxBoxSizer   * m_sizerFrame;

	wxListBox    * destinationBox;

	wxListBox    * neighborBox;



	//route destinations entries

	wxTextCtrl   * interfaceTxt;

	wxTextCtrl   * weightTxt;

	wxString     selectedDestItem; //used for rehighlighting item after refresh



	//neighbor info entries

	wxTextCtrl   * typeTxt;

	wxTextCtrl   * hysterisisTxt;

	wxTextCtrl   * selectMPRTxt;

	wxString     selectedNeighborItem; //used for rehighlighting item after refresh

	



	//settings 1 window pane

	wxTextCtrl   * cmdPromptTxt;

	

	wxCheckBox   * alCheckBox;

	wxCheckBox   * fuzzyCheckBox;

	wxCheckBox   * slowdownCheckBox;



	wxTextCtrl   * helloIntervalTxt;

	wxTextCtrl   * helloJitterTxt;

	wxTextCtrl   * helloTimeoutTxt;

	wxTextCtrl   * tcIntervalTxt;

	wxTextCtrl   * tcJitterTxt;

	wxTextCtrl   * tcTimeoutTxt;

	wxTextCtrl   * hnaIntervalTxt;

	wxTextCtrl   * hnaJitterTxt;

	wxTextCtrl   * hnaTimeoutTxt;



	wxTextCtrl   * hys_upTxt;

	wxTextCtrl   * hys_downTxt;

	wxTextCtrl   * hys_alphaTxt;

	

	wxButton     * buttonOk;

	wxButton     * buttonCancel;



	wxString      helloEntry;



	DECLARE_EVENT_TABLE();

};

class OLSRApp : public wxProtoApp 

{

public:

	OLSRApp();

	~OLSRApp();

    	bool OnInit();

	int OnExit();



	void OnServerEvent(ProtoSocket&       theSocket, 

                           ProtoSocket::Event theEvent);

    	void OnClientEvent(ProtoSocket&       theSocket, 

                           ProtoSocket::Event theEvent);

	bool OnStartup(int argc, const char*const* argv);

	bool OnShutdown();

	bool StringProcessCommands(char* theString);

    	bool ProcessCommands(int argc, const char*const* argv);

	

	//functions for frame to call

	bool UpdateRoutes();

	bool UpdateNeighbors();

	bool SendSettingsString(const char* buffer,unsigned int size);

	bool GetSettings();



private:

	MyFrame* frame;

	bool OnSendTimeout(ProtoTimer& theTimer);



	//functionality

	ProtoTimer   update_timer;

	ProtoPipe    server_pipe;

    	ProtoPipe    client_pipe;

	unsigned int counter;

	char*        msg_buffer;

    	unsigned int msg_len;

    	unsigned int msg_index;

    	int          msg_repeat;

    	int          msg_repeat_count;

	int          update_interval;

	char         serverPipeName[256];

	char         clientPipeName[256];



};

//PROTO_INSTANTIATE_APP(OLSRApp) 

DECLARE_APP(OLSRApp)



class MyDestElement

{

	public:

        wxString destination;

        wxString gateway;

	wxString weight;

        wxString interfaceName;

};



class MyNeighborElement

{

	public:

		wxString neighbor;

		wxString type;

		wxString hysterisis;

		wxString MPRselect;

};



WX_DECLARE_LIST(MyDestElement,MyListDest);

WX_DECLARE_LIST(MyNeighborElement,MyListNeighbor);



enum 

{

	ID_CHOICEBOOK,

	ID_REFRESH_DEST,

	ID_REFRESH_NEIGHBOR,

	ID_CHOICE_DEST,

	ID_CHOICE_NEIGHBOR,

	ID_INTERFACE,

	ID_GET,

	ID_SET,

	ID_SETTINGS_CHANGE_ONE,          //these two lines do the same

	ID_SETTINGS_CHANGE_ONE_CHECKBOX  //these two lines do the same

};

#define ROUTES_PAGE_NAME wxT("Routes")

#define NEIGHBOR_INFO_PAGE_NAME wxT("Neighbor Info")

#define DEBUG_PAGE_NAME wxT("Debug")

#define SETTINGS_PAGE_NAME wxT("Settings")

