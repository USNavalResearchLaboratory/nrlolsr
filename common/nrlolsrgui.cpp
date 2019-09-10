/*#include "wx/wxprec.h"



#ifndef WX_PRECOMP

    #include "wx/wx.h"

#endif*/



#include "nrlolsrgui.h"

#include "wx/listimpl.cpp"

#include "wx/valgen.h"



WX_DEFINE_LIST(MyListDest);

WX_DEFINE_LIST(MyListNeighbor);

MyListDest*     destList     = new MyListDest();

MyListNeighbor* neighborList = new MyListNeighbor();



IMPLEMENT_APP(OLSRApp)



bool OLSRApp::OnInit()

{

	frame = new MyFrame( wxT("OLSR Control") );

	frame->SetSize(wxDefaultCoord, wxDefaultCoord, 240, 320);

	frame->SetMinSize(wxSize(50,50));

	frame->SetMaxSize(wxSize(240,320));

	frame->SetApp(this);

    	frame->Show();



        char cmdstr[256];

	unsigned int cmdlen=0;

	server_pipe.Listen(serverPipeName); //pipe to recieve messages

	client_pipe.Connect(clientPipeName); //send pipe to nrlolsr

	if(client_pipe.IsOpen()){//send the server pipe name to the client so it can connect back

	  strcpy(cmdstr,"guiClientStart ");

	  strcat(cmdstr,serverPipeName);

	  cmdlen=strlen(cmdstr);

	  if(client_pipe.Send(cmdstr,cmdlen)){

	    GetSettings();

	    UpdateRoutes();

	    UpdateNeighbors();

	  }

	} else {
	    wxMessageBox("Not connected to the client pipe \"%s\"\n",clientPipeName);
		wxMessageBox(clientPipeName);
	}

   	return true;

}







wxPanel * MyFrame::CreateRoutesPage(wxBookCtrlBase *parent)

{

    	wxPanel *panel = new wxPanel(parent);

    	wxBoxSizer *sizerPanel = new wxBoxSizer(wxVERTICAL);

	wxGridSizer *gridsizer = new wxGridSizer(2);

	wxGridSizer *gridsizer2 = new wxGridSizer(2);

	

	///////////////////////////

	// Destination & Gateway //

	///////////////////////////



	gridsizer2->Add(new wxStaticText(panel,wxID_ANY,_T("Destination")));

    	gridsizer2->Add(new wxStaticText(panel,wxID_ANY,_T("Gateway")));

	sizerPanel->Add(gridsizer2,wxSizerFlags().Proportion(0).Expand().Border(wxALL, 1));



	destinationBox = new wxListBox(panel,ID_CHOICE_DEST);

	sizerPanel->Add(destinationBox,1,wxEXPAND,1);



	///////////////////////////

	// Additional Info Boxes //

    	///////////////////////////

	

	// Weight //

	weightTxt = new wxTextCtrl(panel, wxID_ANY, _T("")

		,wxDefaultPosition,wxDefaultSize,wxTE_READONLY);

	gridsizer->Add(new wxStaticText(panel, wxID_ANY, _T("Weight"))

		,wxSizerFlags().Align(wxALIGN_RIGHT | wxALIGN_CENTER_VERTICAL));

    	gridsizer->Add(weightTxt

		,wxSizerFlags(1).Align(wxGROW | wxALIGN_CENTER_VERTICAL));



    	// Interface //

	interfaceTxt = new wxTextCtrl(panel, wxID_ANY, _T("")

		,wxDefaultPosition,wxDefaultSize,wxTE_READONLY);

	gridsizer->Add(new wxStaticText(panel, wxID_ANY, _T("Interface"))

		,wxSizerFlags().Align(wxALIGN_RIGHT | wxALIGN_CENTER_VERTICAL));

    	gridsizer->Add(interfaceTxt

		,wxSizerFlags(1).Align(wxGROW | wxALIGN_CENTER_VERTICAL));



	// Add boxes to gridPanel //

    	sizerPanel->Add(gridsizer,wxSizerFlags().Proportion(0).Expand().Border(wxALL, 1));



	////////////////////

	// Refresh Button //

	////////////////////

	sizerPanel->Add(new wxButton(panel,ID_REFRESH_DEST,"Refresh"));



	// Add it all to the panel

	panel->SetSizer(sizerPanel);

    	return panel;

}



wxPanel * MyFrame::CreateNeighborInfoPage(wxBookCtrlBase *parent)

{

     	wxPanel *panel = new wxPanel(parent);

    	wxBoxSizer *sizerPanel = new wxBoxSizer(wxVERTICAL);

	wxGridSizer *gridsizer = new wxGridSizer(2);

		

	////////////////////////

	// Neighbor's Address //

	////////////////////////



	sizerPanel->Add(new wxStaticText(panel,wxID_ANY,_T("Neighbor")));

	neighborBox = new wxListBox(panel,ID_CHOICE_NEIGHBOR);

	sizerPanel->Add(neighborBox,1,wxEXPAND,1);



	///////////////////////////

	// Additional Info Boxes //

 	///////////////////////////

	

	// Type //

	typeTxt = new wxTextCtrl(panel, wxID_ANY, _T("")

		,wxDefaultPosition,wxDefaultSize,wxTE_READONLY);

	gridsizer->Add(new wxStaticText(panel, wxID_ANY, _T("Type"))

		,wxSizerFlags().Align(wxALIGN_RIGHT | wxALIGN_CENTER_VERTICAL));

    	gridsizer->Add(typeTxt

		,wxSizerFlags(1).Align(wxGROW | wxALIGN_CENTER_VERTICAL));



	// Hysterisis //

	hysterisisTxt = new wxTextCtrl(panel, wxID_ANY, _T("")

		,wxDefaultPosition,wxDefaultSize,wxTE_READONLY);

	gridsizer->Add(new wxStaticText(panel, wxID_ANY, _T("Hysterisis"))

		,wxSizerFlags().Align(wxALIGN_RIGHT | wxALIGN_CENTER_VERTICAL));

    	gridsizer->Add(hysterisisTxt

		,wxSizerFlags(1).Align(wxGROW | wxALIGN_CENTER_VERTICAL));



	// Select MPR //

	selectMPRTxt = new wxTextCtrl(panel, wxID_ANY, _T("")

		,wxDefaultPosition,wxDefaultSize,wxTE_READONLY);

	gridsizer->Add(new wxStaticText(panel, wxID_ANY, _T("MPR selector"))

		,wxSizerFlags().Align(wxALIGN_RIGHT | wxALIGN_CENTER_VERTICAL));

    	gridsizer->Add(selectMPRTxt

		,wxSizerFlags(1).Align(wxGROW | wxALIGN_CENTER_VERTICAL));



	// Add boxes to gridPanel //

    	sizerPanel->Add(gridsizer,wxSizerFlags().Proportion(0).Expand().Border(wxALL, 1));



	////////////////////

	// Refresh Button //

	////////////////////



	sizerPanel->Add(new wxButton(panel,ID_REFRESH_NEIGHBOR,"Refresh"));



	// Add it all to the panel

	panel->SetSizer(sizerPanel);

    	return panel;

}



wxPanel * MyFrame::CreateDebugPage(wxBookCtrlBase *parent)

{

    	wxPanel *panel = new wxPanel(parent);



    	wxBoxSizer *sizerPanel = new wxBoxSizer(wxVERTICAL);

    	panel->SetSizer(sizerPanel);



    	return panel;

}



wxPanel * MyFrame::CreateSettingsPage(wxBookCtrlBase *parent)

{

    	wxPanel    * panel      = new wxPanel(parent);

    	wxBoxSizer * sizerPanel = new wxBoxSizer(wxVERTICAL);

	//wxBoxSizer * sizerPanel2 = new wxBoxSizer(wxHORIZONTAL);	



	/////////////////////

	// Interface Input //

	/////////////////////



	wxBoxSizer * sizerTopLineBox = new wxBoxSizer(wxHORIZONTAL);

	sizerTopLineBox->Add(new wxStaticText(panel,wxID_ANY,_T("OLSR:")),2,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	cmdPromptTxt = new wxTextCtrl(panel,ID_SETTINGS_CHANGE_ONE,_T(""));

	sizerTopLineBox->Add(cmdPromptTxt,9,wxALIGN_LEFT | wxALIGN_CENTER);

	sizerPanel->Add(sizerTopLineBox,wxSizerFlags().Proportion(0).Expand().Border(wxALL, 1));



	//////////////////////////

	// TOGGLE OPTIONS       //

	//////////////////////////



	wxStaticBoxSizer* sizerCheckBox = new wxStaticBoxSizer(wxHORIZONTAL,panel,"Toggle settings"); //made of up left and right sizers

	alCheckBox = new wxCheckBox(panel,ID_SETTINGS_CHANGE_ONE_CHECKBOX,_T("alllinks"),wxDefaultPosition,wxDefaultSize,wxEXPAND | wxALL | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL);

	fuzzyCheckBox = new wxCheckBox(panel,ID_SETTINGS_CHANGE_ONE_CHECKBOX,_T("fuzzy"),wxDefaultPosition,wxDefaultSize,wxEXPAND | wxALL | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL);

	slowdownCheckBox = new wxCheckBox(panel, ID_SETTINGS_CHANGE_ONE_CHECKBOX,_T("slowdown"),wxDefaultPosition,wxDefaultSize,wxEXPAND | wxALL | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL);

	

	sizerCheckBox->Add(alCheckBox,3,wxEXPAND | wxALL | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL);

	sizerCheckBox->Add(fuzzyCheckBox,2,wxEXPAND | wxALL | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL);

	sizerCheckBox->Add(slowdownCheckBox,3,wxEXPAND | wxALL | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL);



	sizerPanel->Add(sizerCheckBox,0, wxEXPAND | wxALIGN_CENTER );



	//////////////////////////

	// Hello,TC,HNA Control //

	//////////////////////////

	wxStaticBoxSizer* sizerTimer = new wxStaticBoxSizer(wxHORIZONTAL,panel,"Timer variables"); //made of up left and right sizers

	wxBoxSizer* sizerTimerRight = new wxBoxSizer(wxVERTICAL);

	wxBoxSizer* sizerTimerLeft = new wxBoxSizer(wxVERTICAL);

	//left sizer build (its just text)

	sizerTimerLeft->Add(new wxStaticText(panel,wxID_ANY,_T("")),3,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerTimerLeft->Add(new wxStaticText(panel,wxID_ANY,_T("Hello")),3,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerTimerLeft->Add(new wxStaticText(panel,wxID_ANY,_T("TC")),3,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerTimerLeft->Add(new wxStaticText(panel,wxID_ANY,_T("HNA")),3,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerTimer->Add(sizerTimerLeft,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);



	//right sizer build

	//build title line

	wxBoxSizer* sizerTimerTitle = new wxBoxSizer(wxHORIZONTAL);    

	sizerTimerTitle->Add(new wxStaticText(panel,wxID_ANY,_T("Interval")),3,wxEXPAND | wxALIGN_CENTER | wxALIGN_BOTTOM | wxALL);

	sizerTimerTitle->Add(new wxStaticText(panel,wxID_ANY,_T("Jitter")),3,wxEXPAND | wxALIGN_CENTER | wxALIGN_BOTTOM | wxALL);

	sizerTimerTitle->Add(new wxStaticText(panel,wxID_ANY,_T("Timeout")),3,wxEXPAND | wxALIGN_CENTER | wxALIGN_BOTTOM | wxALL);

	

	//build hello line

	wxBoxSizer* sizerHelloEntry = new wxBoxSizer(wxHORIZONTAL);    

	helloIntervalTxt = new wxTextCtrl(panel, ID_SETTINGS_CHANGE_ONE, _T(""));

	helloJitterTxt = new wxTextCtrl(panel,ID_SETTINGS_CHANGE_ONE, _T(""));

	helloTimeoutTxt = new wxTextCtrl(panel,ID_SETTINGS_CHANGE_ONE, _T(""));

	sizerHelloEntry->Add(helloIntervalTxt,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerHelloEntry->Add(helloJitterTxt,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerHelloEntry->Add(helloTimeoutTxt,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	

	//build tc line

	wxBoxSizer* sizerTCEntry = new wxBoxSizer(wxHORIZONTAL);    

	tcIntervalTxt = new wxTextCtrl(panel,ID_SETTINGS_CHANGE_ONE , _T(""));

	tcJitterTxt = new wxTextCtrl(panel,ID_SETTINGS_CHANGE_ONE, _T(""));

	tcTimeoutTxt = new wxTextCtrl(panel, ID_SETTINGS_CHANGE_ONE, _T(""));

	sizerTCEntry->Add(tcIntervalTxt,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerTCEntry->Add(tcJitterTxt,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerTCEntry->Add(tcTimeoutTxt,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);



	//build hna line

	wxBoxSizer* sizerHNAEntry = new wxBoxSizer(wxHORIZONTAL);    

	hnaIntervalTxt = new wxTextCtrl(panel,ID_SETTINGS_CHANGE_ONE, _T(""));

	hnaJitterTxt = new wxTextCtrl(panel, ID_SETTINGS_CHANGE_ONE, _T(""));

	hnaTimeoutTxt = new wxTextCtrl(panel,ID_SETTINGS_CHANGE_ONE, _T(""));

	sizerHNAEntry->Add(hnaIntervalTxt,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerHNAEntry->Add(hnaJitterTxt,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerHNAEntry->Add(hnaTimeoutTxt,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);



	//put entry fields together with title line

	sizerTimerRight->Add(sizerTimerTitle,0,wxEXPAND | wxALIGN_CENTER);

	sizerTimerRight->Add(sizerHelloEntry,0,wxEXPAND | wxALIGN_CENTER);

	sizerTimerRight->Add(sizerTCEntry,0,wxEXPAND | wxALIGN_CENTER);

	sizerTimerRight->Add(sizerHNAEntry,0,wxEXPAND | wxALIGN_CENTER);



	sizerTimer->Add(sizerTimerRight,3,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerPanel->Add(sizerTimer, 0, wxEXPAND | wxALIGN_CENTER);
	////////////////////////
	// HYS Settings Input //
	////////////////////////
	wxStaticBoxSizer * sizerHys = new wxStaticBoxSizer(wxHORIZONTAL,panel,"Hystersis Values");//made up of left and right sizers

	wxBoxSizer * sizerHysLeft = new wxBoxSizer(wxVERTICAL);

	wxBoxSizer * sizerHysRight = new wxBoxSizer(wxVERTICAL);//made up of two lines

	wxBoxSizer * sizerHysRightTop = new wxBoxSizer(wxHORIZONTAL);//made up of two lines

	wxBoxSizer * sizerHysRightBottom = new wxBoxSizer(wxHORIZONTAL);//made up of two lines

	//build left sizer

	sizerHysLeft->Add(new wxStaticText(panel,wxID_ANY,_T(" ")),1,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerHysLeft->Add(new wxStaticText(panel,wxID_ANY,_T("HYS")),1,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);



	//build right sizer



	//build first line for hys info

	sizerHysRightTop->Add(new wxStaticText(panel,wxID_ANY,_T("Up")),1,wxEXPAND | wxALIGN_CENTER | wxALIGN_BOTTOM | wxALL);

	sizerHysRightTop->Add(new wxStaticText(panel,wxID_ANY,_T("Ddown")),1,wxEXPAND | wxALIGN_CENTER | wxALIGN_BOTTOM | wxALL);

	sizerHysRightTop->Add(new wxStaticText(panel,wxID_ANY,_T("Alpha")),1,wxEXPAND | wxALIGN_CENTER | wxALIGN_BOTTOM | wxALL);



	//build entry (bottom right) line for hys info

	hys_upTxt = new wxTextCtrl(panel, ID_SETTINGS_CHANGE_ONE , _T(""));

	hys_downTxt = new wxTextCtrl(panel, ID_SETTINGS_CHANGE_ONE, _T(""));

	hys_alphaTxt = new wxTextCtrl(panel, ID_SETTINGS_CHANGE_ONE, _T(""));

	sizerHysRightBottom->Add(hys_upTxt,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_BOTTOM |  wxALIGN_CENTER_VERTICAL | wxALL);

	sizerHysRightBottom->Add(hys_downTxt,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_BOTTOM | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerHysRightBottom->Add(hys_alphaTxt,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_BOTTOM | wxALIGN_CENTER_VERTICAL | wxALL);





	sizerHysRight->Add(sizerHysRightTop,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerHysRight->Add(sizerHysRightBottom,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);



	sizerHys->Add(sizerHysLeft,1,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerHys->Add(sizerHysRight,3,wxEXPAND | wxALIGN_CENTER | wxALIGN_CENTER_VERTICAL | wxALL);



	sizerPanel->Add(sizerHys,0,wxALIGN_CENTER | wxEXPAND);



	wxBoxSizer * sizerButtons = new wxBoxSizer(wxHORIZONTAL);	



	buttonOk = new wxButton(panel,ID_SET,"OK");

	buttonOk->Enable(false); //only enable when entries were changed

	buttonCancel = new wxButton(panel,ID_GET,"CANCEL");

	buttonCancel->Enable(false); //only enable when entries were changed

	sizerButtons->Add(buttonOk,3,wxALIGN_RIGHT | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerButtons->Add(new wxStaticText(panel,wxID_ANY,_T(" ")),1);

	sizerButtons->Add(buttonCancel,3,wxALIGN_LEFT | wxALIGN_CENTER_VERTICAL | wxALL);

	sizerPanel->Add(sizerButtons,0,wxALIGN_CENTER);

    	panel->SetSizer(sizerPanel);

    	return panel;

}



void MyFrame::CreateInitialPages(wxBookCtrlBase *parent)

{

	wxPanel *panel = CreateRoutesPage(parent);

   	parent->AddPage( panel, ROUTES_PAGE_NAME, false, -1 );

	

    	panel = CreateNeighborInfoPage(parent);

    	parent->AddPage( panel, NEIGHBOR_INFO_PAGE_NAME, false, -1 );



    	panel = CreateDebugPage(parent);

    	parent->AddPage( panel, DEBUG_PAGE_NAME, false, -1 );



	panel = CreateSettingsPage(parent);

    	parent->AddPage( panel, SETTINGS_PAGE_NAME, false, -1 );



}



wxPanel * MyFrame::CreatePage(wxBookCtrlBase *parent, const wxString&pageName) {

    	if (pageName == ROUTES_PAGE_NAME) {

       		return CreateRoutesPage(parent);

    	}

    	if (pageName == NEIGHBOR_INFO_PAGE_NAME) {

        	return CreateNeighborInfoPage(parent);

    	}

	if (pageName == DEBUG_PAGE_NAME) {

		return CreateDebugPage(parent);

	}

	if (pageName == SETTINGS_PAGE_NAME) {

		return CreateSettingsPage(parent);

	}



	wxFAIL;



    	return (wxPanel *) NULL;

}



bool

OLSRApp::OnStartup(int argc, const char*const* argv){

  return ProcessCommands(argc,argv);

}

bool

OLSRApp::OnShutdown(){

  return true;

}



MyFrame::MyFrame(const wxString& title, const wxPoint& pos, const wxSize& size, long style)

    : wxFrame((wxWindow *) NULL, wxID_ANY, title, pos, size, style)

{

    	m_panel      = (wxPanel *)      NULL;

	m_choicebook = (wxChoicebook *) NULL;

	    

    	m_panel = new wxPanel(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,

        wxTAB_TRAVERSAL | wxCLIP_CHILDREN | wxNO_BORDER | wxNO_FULL_REPAINT_ON_RESIZE);



    	m_sizerFrame = new wxBoxSizer(wxHORIZONTAL);



	RecreateBooks();



    	m_panel->SetSizer(m_sizerFrame);



    	m_sizerFrame->Fit(this);

    	m_sizerFrame->SetSizeHints(this);

}



MyFrame::~MyFrame()

{

	if (!destList->IsEmpty())

	{

        	destList->DeleteContents(true);

        	destList->Clear();

	}

	

	if (!neighborList->IsEmpty())

	{

        	neighborList->DeleteContents(true);

        	neighborList->Clear();

	}



	delete destinationBox;

	delete neighborBox;

}



#define RECREATE( wxBookType , idBook, oldBook , newBook )                         \
{                                                                                  \
    wxBookType *oldBook = newBook;                                                 \
                                                                                   \
    newBook = new wxBookType(m_panel, idBook, wxDefaultPosition, wxDefaultSize,    \
                             wxCHB_DEFAULT);                                       \
                                                                                   \
    if (oldBook)                                                                   \
    {                                                                              \
        int sel = oldBook->GetSelection();                                         \
                                                                                   \
        int count = oldBook->GetPageCount();                                       \
        for (int n = 0; n < count; n++)                                            \
        {                                                                          \
            wxString str = oldBook->GetPageText(n);                                \
                                                                                   \
            wxWindow *page = CreatePage(newBook, str);                             \
            newBook->AddPage(page, str, false, -1 );                               \
        }                                                                          \
                                                                                   \
        m_sizerFrame->Detach(oldBook);                                             \
                                                                                   \
        delete oldBook;                                                            \
                                                                                   \
        if (sel != wxNOT_FOUND)                                                    \
        {                                                                          \
            newBook->SetSelection(sel);                                            \
        }                                                                          \
                                                                                   \
    }                                                                              \
    else                                                                           \
    {                                                                              \
        CreateInitialPages(newBook);                                               \
    }                                                                              \
                                                                                   \
    m_sizerFrame->Insert(0, newBook, 5, wxEXPAND | wxALL, 0);                      \
                                                                                   \
    m_sizerFrame->Hide(newBook);                                                   \
}


void MyFrame::RecreateBooks()

{

  RECREATE( wxChoicebook   , ID_CHOICEBOOK   , notebook   , m_choicebook );

  m_sizerFrame->Show(m_choicebook);

  m_sizerFrame->Layout();

}



BEGIN_EVENT_TABLE(MyFrame,wxFrame)

  EVT_BUTTON(ID_REFRESH_DEST,MyFrame::OnRefreshButton_dest)

  EVT_BUTTON(ID_REFRESH_NEIGHBOR,MyFrame::OnRefreshButton_neighbor)

  EVT_BUTTON(ID_SET,MyFrame::OnSetSettings)

  EVT_BUTTON(ID_GET,MyFrame::OnGetSettings)

  EVT_LISTBOX(ID_CHOICE_DEST,MyFrame::OnListbox_dest)

  EVT_LISTBOX(ID_CHOICE_NEIGHBOR,MyFrame::OnListbox_neighbor)

  EVT_TEXT(ID_SETTINGS_CHANGE_ONE,MyFrame::OnSettingsEditOne)

  EVT_CHECKBOX(ID_SETTINGS_CHANGE_ONE_CHECKBOX,MyFrame::OnSettingsEditOne)

END_EVENT_TABLE()

  

void 

MyFrame::OnSettingsEditOne(wxCommandEvent& event) //settings in panel one were changed event

{

  buttonOk->Enable(true);

  buttonCancel->Enable(true);

}

void MyFrame::OnListbox_dest(wxCommandEvent &event)

{

	long sel = event.GetSelection();



	MyListDest::Node * node = destList->Item(sel);

	MyDestElement * temp = node->GetData();

	weightTxt->SetValue(temp->weight);

	interfaceTxt->SetValue(temp->interfaceName);

	//store the value of the dest so we can select it after clear and refresh

	selectedDestItem=temp->destination;

	selectedNeighborItem="";//unselect neighbor entry

}

void MyFrame::OnListbox_neighbor(wxCommandEvent &event)

{

	long sel = event.GetSelection();



	MyListNeighbor::Node * node = neighborList->Item(sel);

	MyNeighborElement * temp = node->GetData();

	typeTxt->SetValue(temp->type);

	hysterisisTxt->SetValue(temp->hysterisis);

	selectMPRTxt->SetValue(temp->MPRselect);

	

	//store the value of the neighbor so we can select it after clear and refresh

	selectedNeighborItem=temp->neighbor;

	selectedDestItem=""; //unselect dest itme

}

void MyFrame::OnRefreshButton_dest(wxCommandEvent &event)

{	

  theApp->UpdateRoutes();

  for (MyListDest::Node * node = destList->GetFirst(); node; node = node->GetNext())

    {

      MyDestElement * current = node->GetData();

      destinationBox->Append(current->destination + "      " + current->gateway);

    }

}

void 

MyFrame::SetApp(OLSRApp* handle){ 

  theApp=handle; 

}

//OLSRApp calls this after OnRefreshButton_dest

void 

MyFrame::ClearDestEntries(){

  destinationBox->Clear();

  if (!destList->IsEmpty()){

    destList->DeleteContents(true);

    destList->Clear();

  }

  interfaceTxt->Clear();

  weightTxt->Clear();

}



void 
MyFrame::AddDestEntry(const char* dest ,const char* gw,const char* weight,const char* interfacename){
  MyDestElement * element = new MyDestElement();
  element->destination = dest;
  element->gateway = gw;
  element->interfaceName = interfacename;
  element->weight = weight ;
  destList->Append(element);
  //check to see if this item was highlighted before clear
  if(dest==selectedDestItem){
    weightTxt->SetValue(weight);
    interfaceTxt->SetValue(interfacename);
  }
}

void

MyFrame::DisplayDestEntries(){

  int count =0;

  for (MyListDest::Node * node = destList->GetFirst(); node; node = node->GetNext()){

    MyDestElement * current = node->GetData();

    destinationBox->Append(current->destination + "      " + current->gateway);

    if(current->destination==selectedDestItem){

      destinationBox->Select(count);

    }

    count++;

  }

}



void MyFrame::OnRefreshButton_neighbor(wxCommandEvent &event)

{

  theApp->UpdateNeighbors();

} 

void 

MyFrame::ClearNeighborEntries(){

  neighborBox->Clear();

  if (!neighborList->IsEmpty()) {

    neighborList->DeleteContents(true);

    neighborList->Clear();

  }

  typeTxt->Clear();

  hysterisisTxt->Clear();

  selectMPRTxt->Clear();

}



void 

MyFrame::AddNeighborEntry(const char* neighbor,const char* type,const char* hysterisis,const char* MPRselect){

  MyNeighborElement * element = new MyNeighborElement();

  element->neighbor = neighbor;

  element->type = type;

  element->hysterisis = hysterisis;

  element->MPRselect = MPRselect;

  neighborList->Append(element);

  if(neighbor==selectedNeighborItem){

    typeTxt->SetValue(type);

    hysterisisTxt->SetValue(hysterisis);

    selectMPRTxt->SetValue(MPRselect);

  }

}

void 

MyFrame::DisplayNeighborEntries(){

  int count = 0;

  for (MyListNeighbor::Node * node = neighborList->GetFirst(); node; node = node->GetNext()) {

    MyNeighborElement * current = node->GetData();

    neighborBox->Append(current->neighbor);

    if(current->neighbor==selectedNeighborItem){

      neighborBox->Select(count);

    }

    count++;

  }

}



void 

MyFrame::OnGetSettings(wxCommandEvent &event)

{

  if(!theApp->GetSettings()){

    wxMessageBox("Error getting settings pipe may not be open");

  }

}

void 

MyFrame::SetSettings(const char* al, const char* fuzzy, const char* slowdown, 

		     const char* hi, const char* hj, const char* ht,

		     const char* tci, const char* tcj, const char* tct,

		     const char* hnai, const char* hnaj, const char* hnat,

		     const char* up, const char* down, const char* alpha, const char* willingness){

  wxString strValue;

  long intValue;



  strValue=al;

  if(strValue.ToLong(&intValue)){

    if(intValue!=0){

      alCheckBox->SetValue(true);

    } else {

      alCheckBox->SetValue(false);

    }

  }

  strValue=fuzzy;

  if(strValue.ToLong(&intValue)){

    if(intValue!=0){

      fuzzyCheckBox->SetValue(true);

    } else {

      fuzzyCheckBox->SetValue(false);

    }

  }

  strValue=slowdown;

  if(strValue.ToLong(&intValue)){

    if(intValue!=0){

      slowdownCheckBox->SetValue(true);

    } else {

      slowdownCheckBox->SetValue(false);

    }

  }



  strValue=hi;

  helloIntervalTxt->SetValue(strValue);

  strValue=hj;

  helloJitterTxt->SetValue(strValue);

  strValue=ht;

  helloTimeoutTxt->SetValue(strValue);



  strValue=tci;

  tcIntervalTxt->SetValue(strValue);

  strValue=tcj;

  tcJitterTxt->SetValue(strValue);

  strValue=tct;

  tcTimeoutTxt->SetValue(strValue);



  strValue=hnai;

  hnaIntervalTxt->SetValue(strValue);

  strValue=hnaj;

  hnaJitterTxt->SetValue(strValue);

  strValue=hnat;

  hnaTimeoutTxt->SetValue(strValue);



  strValue=up;

  hys_upTxt->SetValue(strValue);

  strValue=down;

  hys_downTxt->SetValue(strValue);

  strValue=alpha;

  hys_alphaTxt->SetValue(strValue);

  //willingness ignored

  buttonOk->Enable(false);

  buttonCancel->Enable(false);

}



void MyFrame::OnSetSettings(wxCommandEvent &event)

{

  //buttonOk->Enable(false);

  //buttonCancel->Enable(false);

  bool waserror=false;

  double tempdouble;

  wxString errorMsg;

  wxString cmd; //single command

  wxString cmdString; //string of commands

  cmdString.Append(cmdPromptTxt->GetValue().c_str());

  if(!cmdString.IsEmpty()) cmdString.Append(" ");  //add space for other options to be sent

  if(alCheckBox->GetValue()){

    cmd.Printf("-al on ");

    cmdString.Append(cmd);

  } else {

    cmd.Printf("-al off ");

    cmdString.Append(cmd);

  }

  if(fuzzyCheckBox->GetValue()){

    cmd.Printf("-fuzzy on ");

    cmdString.Append(cmd);

  } else {

    cmd.Printf("-fuzzy off ");

    cmdString.Append(cmd);

  }

  if(slowdownCheckBox->GetValue()){

    cmd.Printf("-slowdown on ");

    cmdString.Append(cmd);

  } else {

    cmd.Printf("-slowdown off ");

    cmdString.Append(cmd);

  }

  

  //check txt boxes for validity

  //hello boxes

  if(helloIntervalTxt->IsModified()){

    if(helloIntervalTxt->GetValue().ToDouble(&tempdouble)){

      if(tempdouble>0){

	cmd.Printf("-hi %f ",tempdouble);

	cmdString.Append(cmd);

      } else {

	errorMsg.Printf("Error: Hello interval value of \"%s\" seconds must be positive\n",helloIntervalTxt->GetValue().c_str());

	waserror=true;

      }

    } else {

      errorMsg.Printf("Error: Hello interval value of \"%s\" is not in seconds\n",helloIntervalTxt->GetValue().c_str());

      waserror=true;

    }

  }

  if(helloJitterTxt->IsModified()){

    if(helloJitterTxt->GetValue().ToDouble(&tempdouble)){

      if(tempdouble<1 && tempdouble >=0){

	cmd.Printf("-hj %f ",tempdouble);

	cmdString.Append(cmd);

      } else {

	errorMsg.Printf("Error: Hello jitter value of \"%s\" is invalid\n Jitter must be a value between 0-1\n",helloJitterTxt->GetValue().c_str());

	waserror=true;

      }

    } else {

      errorMsg.Printf("Error: Hello jitter value of \"%s\" is invalid\nJitter must be a value betwwen 0-1\n",helloJitterTxt->GetValue().c_str());

      waserror=true;

    } 

  }

 if(helloTimeoutTxt->IsModified()){

    if(helloTimeoutTxt->GetValue().ToDouble(&tempdouble)){

      if(tempdouble>1){

	cmd.Printf("-ht %f ",tempdouble);

	cmdString.Append(cmd);

      } else {

	errorMsg.Printf("Error: Hello timeout factor of \"%s\" hellos\n It must be >1\n",helloTimeoutTxt->GetValue().c_str());

	waserror=true;

      }

    } else {

      errorMsg.Printf("Error: Hello timeout factor of \"%s\" must be a number >1\n",helloTimeoutTxt->GetValue().c_str());

      waserror=true;

    }

  }

 //tc boxes

 if(tcIntervalTxt->IsModified()){

    if(tcIntervalTxt->GetValue().ToDouble(&tempdouble)){

      if(tempdouble>0){

	cmd.Printf("-tci %f ",tempdouble);

	cmdString.Append(cmd);

      } else {

	errorMsg.Printf("Error: TC interval value of \"%s\" seconds must be positive\n",tcIntervalTxt->GetValue().c_str());

	waserror=true;

      }

    } else {

      errorMsg.Printf("Error: TC interval value of \"%s\" is not in seconds\n",tcIntervalTxt->GetValue().c_str());

      waserror=true;

    }

  }

  if(tcJitterTxt->IsModified()){

    if(tcJitterTxt->GetValue().ToDouble(&tempdouble)){

      if(tempdouble<1 && tempdouble >=0){

	cmd.Printf("-tcj %f ",tempdouble);

	cmdString.Append(cmd);

      } else {

	printf("whats goin on\n");

	errorMsg.Printf("Error: TC jitter value of \"%s\" is invalid\n Jitter must be a value between 0-1\n",tcJitterTxt->GetValue().c_str());

	waserror=true;

      }

    } else {

      errorMsg.Printf("Error: TC jitter value of \"%s\" is invalid\nJitter must be a value betwwen 0-1\n",tcJitterTxt->GetValue().c_str());

      waserror=true;

    } 

  }

 if(tcTimeoutTxt->IsModified()){

    if(tcTimeoutTxt->GetValue().ToDouble(&tempdouble)){

      if(tempdouble>1){

	cmd.Printf("-tct %f ",tempdouble);

	cmdString.Append(cmd);

      } else {

	errorMsg.Printf("Error: TC timeout factor of \"%s\" tcs\n It must be greater than 1\n",tcTimeoutTxt->GetValue().c_str());

	waserror=true;

      }

    } else {

      errorMsg.Printf("Error: TC timeout factor of \"%s\" is invalid\n It must be > 1",tcTimeoutTxt->GetValue().c_str());

      waserror=true;

    }

  }

 //hna boxes

 if(hnaIntervalTxt->IsModified()){

    if(hnaIntervalTxt->GetValue().ToDouble(&tempdouble)){

      if(tempdouble>0){

	cmd.Printf("-hnai %f ",tempdouble);

	cmdString.Append(cmd);

      } else {

	errorMsg.Printf("Error: HNA interval value of \"%s\" seconds must be positive\n",hnaIntervalTxt->GetValue().c_str());

	waserror=true;

      }

    } else {

      errorMsg.Printf("Error: HNA interval value of \"%s\" is not in seconds\n",hnaIntervalTxt->GetValue().c_str());

      waserror=true;

    }

  }

  if(hnaJitterTxt->IsModified()){

    if(hnaJitterTxt->GetValue().ToDouble(&tempdouble)){

      if(tempdouble<1 && tempdouble >=0){

	cmd.Printf("-hnaj %f ",tempdouble);

	cmdString.Append(cmd);

      } else {

	errorMsg.Printf("Error: HNA jitter value of \"%s\" is invalid\n Jitter must be a value between 0-1\n",hnaJitterTxt->GetValue().c_str());

	waserror=true;

      }

    } else {

      errorMsg.Printf("Error: HNA jitter value of \"%s\" is invalid\nJitter must be a value betwwen 0-1\n",hnaJitterTxt->GetValue().c_str());

      waserror=true;

    } 

  }

  if(hnaTimeoutTxt->IsModified()){

    if(hnaTimeoutTxt->GetValue().ToDouble(&tempdouble)){

      if(tempdouble>1){

	cmd.Printf("-hnat %f ",tempdouble);

	cmdString.Append(cmd);

      } else {

	errorMsg.Printf("Error: HNA timeout factor of \"%s\" hnas\n It must be greater than 1\n",hnaTimeoutTxt->GetValue().c_str());

	waserror=true;

      }

    } else {

      errorMsg.Printf("Error: HNA timeout factor of \"%s\" is not an number >1\n",hnaTimeoutTxt->GetValue().c_str());

      waserror=true;

    }

  }

  //hys boxes

  if(hys_upTxt->IsModified() || hys_downTxt->IsModified()){//these variables are linked together

    double tempdouble2;

    if(!hys_upTxt->GetValue().ToDouble(&tempdouble)){

      errorMsg.Printf("Error: HYS up value of \"%s\" is invalid\nMust be a value between 0-1\n",hys_upTxt->GetValue().c_str());

      waserror=true;

    } else {//make sure its in the 0-1 range

      if(tempdouble>=1 || tempdouble <=0){

	errorMsg.Printf("Error: HYS up value of \"%s\" is invald\nMust be a value between 0-1\n",hys_upTxt->GetValue().c_str());

	waserror=true;

      }

    }

    if(!hys_downTxt->GetValue().ToDouble(&tempdouble2)){

      errorMsg.Printf("Error: HYS down value of \"%s\" is invalid\nMust be a value between 0-1\n",hys_downTxt->GetValue().c_str());

      waserror=true;

    } else { //make sure it is in the 0-1 range

      if(tempdouble2>=1 || tempdouble2 <=0){

	errorMsg.Printf("Error: HYS down value of \"%s\" is invald\nMust be a value between 0-1\n",hys_downTxt->GetValue().c_str());

	waserror=true;

      }

    }

    if(!waserror){

      if(tempdouble<tempdouble2){ //upvalue < down value  

	errorMsg.Printf("Error: HYS down value of \"%s\" is greater than HYS up value of \"%s\"\nup must be > down",hys_downTxt->GetValue().c_str(),hys_upTxt->GetValue().c_str());

	waserror=true;

      } else {

	cmd.Printf("-hys up %f -hys down %f ",tempdouble,tempdouble2);

	cmdString.Append(cmd);

      }

    }

  }

  if(hys_alphaTxt->IsModified()){

    if(hys_alphaTxt->GetValue().ToDouble(&tempdouble)){

      if(tempdouble>0 && tempdouble <1){

	cmd.Printf("-hys alpha %f ",tempdouble);

	cmdString.Append(cmd);

      } else {

	errorMsg.Printf("Error: HYS alpha value of \"%s\" is invalid\nMust be a value between 0-1\n",hys_alphaTxt->GetValue().c_str());

	waserror= true;

      }

    } else {

      errorMsg.Printf("Error: HYS alpha value of \"%s\" is invalid\nMust be a value between 0-1\n",hys_alphaTxt->GetValue().c_str());

      waserror= true;

    }

  }

  if(waserror){

    wxMessageBox(errorMsg);

  } else {

    buttonOk->Enable(false);

    buttonCancel->Enable(false);

    helloIntervalTxt->SetValue(helloIntervalTxt->GetValue()); //set to change is modified flag

    helloJitterTxt->SetValue(helloJitterTxt->GetValue()); //set to change is modified flag

    helloTimeoutTxt->SetValue(helloTimeoutTxt->GetValue()); //set to change is modified flag

    tcIntervalTxt->SetValue(tcIntervalTxt->GetValue()); //set to change is modified flag

    tcJitterTxt->SetValue(tcJitterTxt->GetValue()); //set to change is modified flag

    tcTimeoutTxt->SetValue(tcTimeoutTxt->GetValue()); //set to change is modified flag

    hnaIntervalTxt->SetValue(hnaIntervalTxt->GetValue()); //set to change is modified flag

    hnaJitterTxt->SetValue(hnaJitterTxt->GetValue()); //set to change is modified flag

    hnaTimeoutTxt->SetValue(hnaTimeoutTxt->GetValue()); //set to change is modified flag

    hys_upTxt->SetValue(hys_upTxt->GetValue());

    hys_downTxt->SetValue(hys_downTxt->GetValue());

    hys_alphaTxt->SetValue(hys_alphaTxt->GetValue());

    //wxMessageBox(cmdString);

    if(' '==cmdString.Last())

      cmdString.RemoveLast(); //get rid of last white space char

    theApp->SendSettingsString(cmdString.c_str(),cmdString.Length());

  }

}



OLSRApp::OLSRApp()

: server_pipe(PIPE_TYPE), client_pipe(PIPE_TYPE),

   msg_buffer(NULL), msg_len(0), msg_index(0),

     msg_repeat(0), msg_repeat_count(0)

{

        strncpy(clientPipeName,"nrlolsr",256);

        strncpy(serverPipeName,"nrlolsrgui",256);

	update_interval=5; //in seconds

	update_timer.SetListener(this, &OLSRApp::OnSendTimeout);

    	update_timer.SetInterval(update_interval);

    	update_timer.SetRepeat(-1);

	ActivateTimer(update_timer);

    	server_pipe.SetNotifier(&GetSocketNotifier());

    	server_pipe.SetListener(this, &OLSRApp::OnServerEvent);

    	client_pipe.SetNotifier(&GetSocketNotifier());

    	client_pipe.SetListener(this, &OLSRApp::OnClientEvent);

}

OLSRApp::~OLSRApp()

{

  TRACE("OLSRApp::~OLSRApp()");

    if (update_timer.IsActive()) update_timer.Deactivate();

    if (server_pipe.IsOpen()) server_pipe.Close();

    if (client_pipe.IsOpen()) client_pipe.Close();

    if (msg_buffer)

    {

        delete[] msg_buffer;

        msg_buffer = NULL;   

    }

}



int OLSRApp::OnExit()

{

    if (update_timer.IsActive()) update_timer.Deactivate();

    if (server_pipe.IsOpen()) server_pipe.Close();

    if (client_pipe.IsOpen()) client_pipe.Close();

    if (msg_buffer)

    {

        delete[] msg_buffer;

        msg_buffer = NULL;   

    }    TRACE("OLSRApp::OnExit() ...\n");



    if (frame)

      {

      //delete[] frame;

       frame=NULL;

    }

    return 0;

} 



bool

OLSRApp::StringProcessCommands(char* theString){

  char *stringPtrStart=theString;

  char *stringPtrEnd=theString;

  char space = ' ';

  char *argv[256]; 

  int argc=1;

  int wordsize;

  while(stringPtrStart){

    stringPtrEnd = strchr(stringPtrStart,space);

    if(stringPtrEnd!=NULL){

      wordsize = stringPtrEnd-stringPtrStart;

      argv[argc]=new char[wordsize+1];

      memset(argv[argc],0,wordsize+1);

      strncpy(argv[argc],stringPtrStart,wordsize);

      argc++;

      stringPtrStart=stringPtrEnd+1;

    } else {//last word

      wordsize = strlen(stringPtrStart);

      argv[argc]=new char[wordsize+1];

      memset(argv[argc],0,wordsize+1);

      //      fprintf(stderr,"%d is strlen\n",wordsize);

      strncpy(argv[argc],stringPtrStart,wordsize);

      argc++;

      stringPtrStart=stringPtrEnd; //or NULL

    }

  }

  bool returnvalue = ProcessCommands(argc,argv);

  for(int i=1;i<argc;i++){

    delete[] argv[i];

  }

  return returnvalue;

}



bool 

OLSRApp::ProcessCommands(int argc, const char*const* argv){

  bool printusage = false;

  /*DMSG(0,"OLSRApp I have to parce the message now \n");

    for(int j=1;j<argc;j++){

    DMSG(0,"%d:%s\n",j,argv[j]);

    }*/

  for(int i=1;i<argc;i++){

    if(!strcmp(argv[i],"guiServerStart")){

      i++;

      if(client_pipe.IsOpen()) client_pipe.Close();

      if(!client_pipe.Connect(argv[i])){

	fprintf(stdout,"%d is the difference between strings\n",strcmp("nrlolsr",argv[i]));

	DMSG(0,"OLSRApp::ProcessCommands(): Error connecting to client_pipe of name %s\n",argv[i]);

	printusage = true;

      } else {

	GetSettings();

	UpdateRoutes();

	UpdateNeighbors();

      }

    } else if(!strcmp(argv[i],"routes")){

      frame->ClearDestEntries();

      i++;

      for(;i+4<argc;i+=4){

	frame->AddDestEntry(argv[i],argv[i+1],argv[i+2],argv[i+3]);

      }

      frame->DisplayDestEntries();

    } else if(!strcmp(argv[i],"neighbors")){

      frame->ClearNeighborEntries();

      i++;

      //add loop to add entries

      for(;i+4<argc;i+=4){

	frame->AddNeighborEntry(argv[i+ 0],argv[i+ 1],argv[i+ 2],argv[i+ 3]);

      }

      frame->DisplayNeighborEntries();

    } else if(!strcmp(argv[i],"settings")){

      i++;

      frame->SetSettings(argv[i+ 0],argv[i+ 1],argv[i+ 2],//al fuzzy slowdown

			 argv[i+ 3],argv[i+ 4],argv[i+ 5],//hi hj ht

			 argv[i+ 6],argv[i+ 7],argv[i+ 8],//tci tcj tct

			 argv[i+ 9],argv[i+10],argv[i+11],//hnai hnaj hnat

			 argv[i+12],argv[i+13],argv[i+14],//up down alpha

			 argv[i+15]);                     //willingness


      i+=16;

    }

  }

  if(printusage){

    return false;

  }

  return true;

}





void 

OLSRApp::OnServerEvent(ProtoSocket&       /*theSocket*/, 

                            ProtoSocket::Event theEvent)

{

  if (theEvent == ProtoSocket::RECV) {

    char buffer[8192];

    unsigned int len = 8191;

    if (server_pipe.Recv(buffer, len)){

      buffer[len]=0;

      if (len) {

	StringProcessCommands(buffer);

      }

    } else {
		DMSG(0,"NrlOlsrGui::OnServerEvent: serverpipe.Recv() error\n");
    }

  }

}

	

void OLSRApp::OnClientEvent(ProtoSocket&       /*theSocket*/, 

                            ProtoSocket::Event theEvent)

{

    switch (theEvent)

    {

        case ProtoSocket::CONNECT:

             DMSG(0, "OLSRApp: client connected to server.\n");

             break;

        case ProtoSocket::RECV:

        {

            TRACE("OLSRApp: client RECV event ...\n");

            break;

        }

        case ProtoSocket::SEND:

            TRACE("OLSRApp: client SEND event ...\n");

            OnSendTimeout(update_timer);

            break;

        case ProtoSocket::DISCONNECT:

            TRACE("OLSRApp: client DISCONNECT event ...\n");

            client_pipe.Close();

            break;

        default:

            TRACE("OLSRApp::OnClientEvent(%d) unhandled event type\n", theEvent);

            break;

        

    }  // end switch(theEvent)

}  // end PipeExample::OnClientEvent()



bool OLSRApp::OnSendTimeout(ProtoTimer& /*theTimer*/)

{

  bool returnvalue;

  returnvalue = UpdateRoutes();

  returnvalue &= UpdateNeighbors();

  if(!returnvalue){

    DMSG(0,"OLSRApp::OnSendTimeout error getting olsr info.\n");

  }

  return true;

  //return returnvalue;

}



bool

OLSRApp::UpdateRoutes(){

  //send request to nrlolsr

    char buffer[256];

    memset((void*)buffer,0,255);

    buffer[255] = '\0';

    strcpy(buffer,"-sendGuiRoutes");

    unsigned int len=sizeof(buffer);



  if(client_pipe.IsOpen()){

    if(!client_pipe.Send(buffer,len)){

      frame->ClearDestEntries();

      DMSG(0,"OLSRApp::UpdateRoutes() client_pipe.Send() error. Pipe name is %s\n",clientPipeName);

      return false;

    }

  } else {

    frame->ClearDestEntries();

    DMSG(0,"OLSRApp::UpdateRoutes() client_pipe %s is not open! Cannot send request for update.\n",clientPipeName);

    return false;

  }

  return true;

}



bool

OLSRApp::UpdateNeighbors(){

  //send request to nrlolsr

    char buffer[256];

    memset((void*)buffer,0,255);

    buffer[255] = '\0';

    strcpy(buffer,"-sendGuiNeighbors");

    unsigned int len=sizeof(buffer);



  if(client_pipe.IsOpen()){

    if(!client_pipe.Send(buffer,len)){

      frame->ClearNeighborEntries();

      DMSG(0,"OLSRApp::UpdateNeighbors() client_pipe.Send() error. Pipe name is %s\n",clientPipeName);

      return false;

    }

  } else {

    frame->ClearNeighborEntries();

    DMSG(0,"OLSRApp::UpdateNeighbors() client_pipe %s is not open! Cannot send request for update.\n",clientPipeName);

    return false;

  }

  return true;

}

bool

OLSRApp::GetSettings(){

  //send request to nrlolsr

    char buffer[256];

    memset((void*)buffer,0,255);

    buffer[255] = '\0';

    strcpy(buffer,"-sendGuiSettings");

    unsigned int len=sizeof(buffer);



  if(client_pipe.IsOpen()){

    if(!client_pipe.Send(buffer,len)){

      DMSG(0,"OLSRApp::GetSettings() client_pipe.Send() error. Pipe name is %s\n",clientPipeName);

      return false;

    }

  } else {

    DMSG(0,"OLSRApp::GetSettings() client_pipe %s is not open! Cannot send request for update.\n",clientPipeName);

    return false;

  }

  return true;

}



bool

OLSRApp::SendSettingsString(const char* buffer, unsigned int size){

  if(client_pipe.IsOpen()){

    if(!client_pipe.Send(buffer,size)){

      DMSG(0,"OLSRApp:: SendSettingsString() client_pipe.Send() error. Pipe name is %s\n",clientPipeName);

      return false;

    }

  } else {

    DMSG(0,"OLSRApp::SendSettingsString() client_pipe %s is not open! Cannot send request for update.\n",clientPipeName);

    return false;

  }

  return true;

}

