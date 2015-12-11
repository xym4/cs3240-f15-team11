from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth import authenticate, logout
from django.http import HttpResponse, HttpResponseRedirect
from projectSite import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from reports.models import Report, Folder
from .forms import ReportForm, UserForm, FolderForm, MoveToFolderForm
from django.template import RequestContext, loader
from django.utils import timezone
from django.contrib.auth import models
from django.contrib.auth.models import User, Group
from django.contrib import messages
from .forms import GivePermissionsForm, SuspensionForm, UnsuspensionForm
from django.contrib.auth.decorators import user_passes_test
import re
from django.db.models import Q
from memos.models import Key
from Crypto.PublicKey import RSA
from Crypto import Random
from django.contrib.auth.models import User, Group
from rest_framework import viewsets
from index.serializers import UserSerializer, GroupSerializer, ReportSerializer
from rest_framework import permissions
from index.permissions import IsOwnerOrInGroupOrReadOnly


#####################SEARCH STUFF########################################################

#http://julienphalip.com/post/2825034077/adding-search-to-a-django-site-in-a-snap
def normalize_query(query_string,
                    findterms=re.compile(r'"([^"]+)"|(\S+)').findall,
                    normspace=re.compile(r'\s{2,}').sub):
    ''' Splits the query string in invidual keywords, getting rid of unecessary spaces
        and grouping quoted words together.
        Example:
        
        >>> normalize_query('  some random  words "with   quotes  " and   spaces')
        ['some', 'random', 'words', 'with quotes', 'and', 'spaces']
    
    '''
    return [normspace(' ', (t[0] or t[1]).strip()) for t in findterms(query_string)] 

def get_query(query_string, search_fields):
    ''' Returns a query, that is a combination of Q objects. That combination
        aims to search keywords within a model by testing the given search fields.
    
    '''
    query = None # Query to search for every search term        
    terms = normalize_query(query_string)
    for term in terms:
        or_query = None # Query to search for a given term in each field
        for field_name in search_fields:
            q = Q(**{"%s__icontains" % field_name: term})
            if or_query is None:
                or_query = q
            else:
                or_query = or_query | q
        if query is None:
            query = or_query
        else:
            query = query & or_query
    return query

@login_required
def search(request):
    query_string = ''
    found_reports = None
    show_these_reports = None
    if ((('q' in request.GET) and request.GET['q'].strip()) or (('titleq' in request.GET) and request.GET['titleq'].strip()) or (('sdescripq' in request.GET) and request.GET['sdescripq'].strip()) or (('descripq' in request.GET) and request.GET['descripq'].strip()) or (('locationq' in request.GET) and request.GET['locationq'].strip())):
        query_string = request.GET['q']
        title_query_string = request.GET['titleq']
        print("Title" + title_query_string)
        sDescrip_query_string = request.GET['sdescripq']
        print("Short Descrip Q" + sDescrip_query_string)
        dDescrip_query_string = request.GET['descripq']
        print("Long Descrip Q" + dDescrip_query_string)
        loc_query_string = request.GET['locationq']
        print("Loc " + loc_query_string)
        
        report_query = get_query(query_string, ['title', 'Detailed_Description',])

        treport_query = (get_query(title_query_string, ['title',]))
        sDreport_query = get_query(sDescrip_query_string, ['Short_Description',])
        dDreport_query = get_query(dDescrip_query_string, ['Detailed_Description',])
        lreport_query = get_query(loc_query_string, ['Location_of_Event',])


        global_found = Report.objects.all()

        if (query_string != '') :
            global_found = global_found.filter(report_query)
            print(global_found)

        if (title_query_string != '') :
            global_found = global_found.filter(treport_query)
            print(global_found)

        if (sDescrip_query_string != '') :
            global_found = global_found.filter(sDreport_query)
            print(global_found)

        if (dDescrip_query_string != '') :
            global_found = global_found.filter(dDreport_query)
            print(global_found)

        if (loc_query_string != '') :
            global_found = global_found.filter(lreport_query)
            print(global_found)


        global_found = global_found.order_by('-created')


        #found_reports = Report.objects.filter(treport_query).order_by('-created')
        #found_reports = Report.objects.filter(sDreport_query).order_by('-created')
        #found_reports = Report.objects.filter(dDreport_query).order_by('-created')
        #found_reports = Report.objects.filter(lreport_query).order_by('-created')

        show_these_reports = []

        vgroupnames = request.user.groups.values_list('name',flat=True)

        for rep in global_found:
            if rep.group_name in vgroupnames or 'SiteManager' in vgroupnames:
                show_these_reports.append(rep)

    return render(request,'index/search_results.html', { 'query_string': query_string, 'show_these_reports': show_these_reports })

#######################USER AUTHENTICATION STUFF########################################################

def Register(request):
    context = RequestContext(request)
    registered = False

    if request.method == 'POST':
        user_form = UserForm(data=request.POST)

        if user_form.is_valid() :
            user = user_form.save()
            user.set_password(user.password)

            # public_group = Group.objects.get(name='Public')
            public_group, created = Group.objects.get_or_create(name='Public')
            public_group.user_set.add(user)

            user.save()
            registered = True
            print("USER SUCCESS!")
        else:
            print("USER ERROR!")
    else:
        user_form = UserForm()
    # user_form = UserForm()
    return render(request, 'index/register.html', {'user_form': user_form})

def Login(request):
    next = request.GET.get('next', '/memos/inbox/')
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)

        if user is not None:
            if user.is_active:
                login(request, user)
                return HttpResponseRedirect(next)
            else:
                return HttpResponse("Inactive user.")
        else:
            return HttpResponseRedirect(settings.LOGIN_URL)

    return render(request, "index/login.html", {'redirect_to': next})

def Logout(request):
    logout(request)
    return HttpResponseRedirect(settings.LOGIN_URL)

@login_required
def Home(request):
    userIsSiteManager = isSiteManager(request.user)
    return render(request, "index/home.html", {"userIsSiteManager": userIsSiteManager})

def checkIfUserisSM(request):
    valid_groups = request.user.groups.all()
    valid_group_names = []

    for g in valid_groups:
        valid_group_names.append(g.name)

    if 'SiteManager' in valid_group_names:
        return True
    else:
        return False

def isSiteManager(user):
    return user.groups.filter(name='SiteManager').exists()

@login_required
def YourReports(request):
    your_reports_list = []
    all_reports = Report.objects.all()
    your_folders_list = []
    all_folders = Folder.objects.all()

    your_unsorted_reports = []

    for folder in all_folders:
        if folder.creator.username == request.user.username:
            your_folders_list.append(folder)

    for rep in all_reports:
        if rep.author.username == request.user.username:
            your_reports_list.append(rep)

    for rep in your_reports_list:
        if rep.folder == None:
            your_unsorted_reports.append(rep)
    print("ALL OF THE REPORTS YOU CREATED: ", your_reports_list)
    print("ALL OF THE Folders YOU CREATED: ", your_folders_list)

    return render(request, 'index/yourreports.html', {'your_reports_list': your_reports_list, 'your_folders_list': your_folders_list, 'your_unsorted_reports': your_unsorted_reports})

############################REPORT STUFF##################################################################

@login_required
def ReportList(request): #Shows a list of all the reports you have permission to see

    userIsSiteManager = checkIfUserisSM(request)
    reports_list = Report.objects.order_by('title')
    
    has_permission_to_view_reports_list = []

    valid_groups = request.user.groups.all()
    valid_group_names = []

    for g in valid_groups:
        valid_group_names.append(g.name)

    print("THE GROUP", valid_group_names)

    for item in reports_list:
        print(item.group_name)
        if item.group_name in valid_group_names or userIsSiteManager:
            print("VALID!!")
            has_permission_to_view_reports_list.append(item)

    print("HAS PERMISSION", has_permission_to_view_reports_list)

    print(reports_list)
    template = loader.get_template('index/report.html')
    # context = {'reports_list': reports_list}
    context = {'has_permission_to_view_reports_list': has_permission_to_view_reports_list}
    return render(request, 'index/report.html', context)

@login_required
def create(request): #Allows you to create a new report
    download_url = ""
    if request.method == "POST":
        # form = ReportForm(request.POST, request.FILES)
        form = ReportForm(request.POST, request.FILES)

        if form.is_valid():
            report = form.save(commit=False)
            report.author = request.user
            report.created = timezone.now()
            
            #if created == False, means that group already exists
            new_group, created = Group.objects.get_or_create(name=report.group_name)

            if created == True:
                print("TRUEEEEEEEEEEEEEEEEE")
                new_group.user_set.add(request.user)

                admin_users = Group.objects.get(name='SiteManager').user_set.all()
                print("ADMIN USERS HERE: ", admin_users)
                for member in admin_users:
                    print(type(member), type(request.user))
                    new_group.user_set.add(member)
                    print("NEW GROUP: ", new_group.user_set.all())
                    new_group.save()

                report.save()

                # return redirect('index.Home')

            else:
                valid_users = new_group.user_set.all()
                print("HEEY", valid_users)

                userIsSiteManager = checkIfUserisSM(request)

                if request.user not in valid_users and not userIsSiteManager:
                    print("You are not allowed to post to this group.")
                    # messages.error(request, 'Document deleted.')
                    # pass
                else:
                    report.save()

                # new_group.save()
                # current_user = request.user
                # current_user.groups.add(new_group)
                # current_user.save()

            # return render(request, 'index/report.html')
            return redirect('index.views.detail', report_id=report.pk)

    else:
        form = ReportForm
    return render(request, 'index/create.html', {'form': form})

@login_required
def detail(request, report_id): #This is when you try to look at a specific report
    r = get_object_or_404(Report, pk=report_id)

    authorIsViewing = False

    print("THIS IS THE NAME OF THE REPORT", r.Attachments.name, r.Attachment_is_Encrypted)

    attachment_link = '/media/' + str(r.Attachments)

    siteManagerIsViewing = isSiteManager(request.user)

    if request.method == "POST":
        form = MoveToFolderForm(request.POST)
        possibly_new_folder, created = Folder.objects.get_or_create(Folder_Name=request.POST.get('folder_to_move_to'))
        if created:
            possibly_new_folder.creator=request.user
            possibly_new_folder.save()

        r.folder = possibly_new_folder
        r.save()
        return redirect('index.views.YourReports')
    else:
        form = MoveToFolderForm()

    if r.author.username == request.user.username:
        # print("HEY THE AUTHOR IS LOOKING AT THE REPORT THEY CREATED")
        authorIsViewing = True
    else:
        print("Some random rando is looking at a random report")
    return render(request, 'index/detail.html', {'r': r, 'attachment_link': attachment_link,'authorIsViewing': authorIsViewing, 'siteManagerIsViewing': siteManagerIsViewing, 'form':form})    

@login_required
def EditReport(request, report_id):
    r = get_object_or_404(Report, pk=report_id)

    if request.method == "POST":
        form = ReportForm(request.POST, request.FILES, instance=r)
        if form.is_valid():
            r = form.save(commit=False)
            r.author = request.user
            r.created = timezone.now()

            possibly_new_group, created = Group.objects.get_or_create(name=r.group_name)

            if created:
                possibly_new_group.user_set.add(request.user)
                print("Edit successful, new group created.")
                r.save()
            else:
                valid_groups = request.user.groups.all()
                valid_group_names = []

                for g in valid_groups:
                    valid_group_names.append(g.name)
                    # print("HERE ARE THE VALID EDIT GROUPS", g, type(g.name))

                # print("VVVVVVVV", valid_groups, r.group_name, type(r.group_name))

                if r.group_name in valid_group_names or "SiteManager" in valid_group_names:
                    print("Edit success: you are allowed to post in this group")
                    r.save()

                else:
                    print("You do not have permission to change group name to this group")

            return redirect('index.views.detail', report_id=r.pk)
    else:
        form = ReportForm(instance=r)
    return render(request, 'index/create.html', {'form': form})

@login_required
def DeleteReport(request, report_id):
    Report.objects.filter(id=report_id).delete()
    return redirect('index.views.ReportList')   

###############################FOLDER STUFF##################################################################

@login_required
def CreateFolder(request):
    if request.method == "POST":
        form = FolderForm(request.POST)
        if form.is_valid():
            folder = form.save(commit=False)
            folder.creator = request.user

            if request.POST.get("Folder_Name") == None:
                return redirect('index.views.CreateFolder')
            else:
                new_folder, created = Folder.objects.get_or_create(Folder_Name=request.POST.get("Folder_Name"))
                if created == False:
                    print("This folder already exists.")
                else:
                    print("A new folder was created!")
                    new_folder.creator = request.user
                    new_folder.save()
            return redirect('index.views.YourReports')    
    else:
        form = FolderForm
    return render(request, 'index/createfolder.html', {'form': form})

@login_required
def FolderDetails(request, folder_id):
    f = get_object_or_404(Folder, pk=folder_id)
    reports_in_folder = Report.objects.filter(folder=f)
    return render(request, 'index/folderdetail.html', {'f': f, 'reports_in_folder': reports_in_folder})

@login_required
def RemoveFolder(request, folder_id):
    f = get_object_or_404(Folder, pk=folder_id)
    reports_in_folder = Report.objects.filter(folder=f)
    for rep in reports_in_folder:
        rep.folder=None
        rep.save()
    Folder.objects.filter(id=f.id).delete() 
    return redirect('index.views.YourReports')     

@login_required
def DeleteReportsInFolder(request, folder_id):
    f = get_object_or_404(Folder, pk=folder_id)
    reports_in_folder = Report.objects.filter(folder=f)
    for rep in reports_in_folder:
        Report.objects.filter(id=rep.id).delete()   
    return redirect('index.views.FolderDetails', folder_id=folder_id)     

@login_required
def RenameFolder(request, folder_id):
    f = get_object_or_404(Folder, pk=folder_id)

    if request.method == "POST":
        form = FolderForm(request.POST, instance=f)
        if form.is_valid():
            f = form.save(commit=False)
            f.Folder_Name = request.POST.get('Folder_Name')
            f.creator = request.user
            f.save()
            return redirect('index.views.FolderDetails', folder_id=f.pk)
    else:
        form = FolderForm(instance=f)
    return render(request, 'index/createfolder.html', {'form': form})

@login_required
def RemoveReportFromFolder(request, report_id):
    r = get_object_or_404(Report, pk=report_id)
    r.folder = None
    r.save()
    return redirect('index.views.YourReports')

#####################GRANTING PERMISSIONS TO OTHER USERS###################################################

@login_required
def GivePermissions(request):

    valid_groups = request.user.groups.all()
    valid_group_names = []

    for g in valid_groups:
        valid_group_names.append(g.name)

    if 'SiteManager' in valid_group_names:
        valid_groups = Group.objects.all()
        valid_group_names = []
        for g in valid_groups:
            valid_group_names.append(g.name)

    if request.method == "POST":
        permission_form = GivePermissionsForm(request.POST)

        selected_user = str(request.POST.get("user"))
        print("SELECTED USER NAME: ", selected_user)
        selected_user_obj = User.objects.get(pk=selected_user)
        print("SELCTED USER OBJ: ", selected_user_obj, type(selected_user_obj))

        selected_group = request.POST.get("group")

        if selected_group in valid_group_names:
            print("HOORAY, selected group is in valid_group names")
            possible_group = Group.objects.get(name=selected_group)
            possible_group.user_set.add(selected_user)

        else:
            print("This group does not exist or you do not have permission to add people to this group")

        print(request.POST.get("user"))
    else:
        permission_form = GivePermissionsForm()

    return render(request, 'index/givepermissions.html', {'permission_form': permission_form, 'valid_group_names': valid_group_names})

#####################ACCOUNT SUSPENSION STUFF FOR SITEMANAGERS################################################

@user_passes_test(isSiteManager, login_url='/home/')
def Suspension(request):
    if 'suspend_button' in request.POST:
        suspension_form = SuspensionForm(request.POST)
        selected_user = str(request.POST.get("active_users"))
        print("SELECTED USER NAME FOR SUSPENSION: ", selected_user)
        selected_user_obj = User.objects.get(pk=selected_user)
        print("SELCTED USER OBJ for SUSPENSION: ", selected_user_obj, type(selected_user_obj))
        selected_user_obj.is_active=False
        selected_user_obj.save()
        return redirect('index.views.Home')
    
    elif 'unsuspend_button' in request.POST:
        unsuspension_form = SuspensionForm(request.POST)
        # selected_user = str(request.POST.get("suspended_users"))
        if request.POST.get("suspended_users") == None:
            return redirect('index.views.Suspension')
        selected_user = str(request.POST.get("suspended_users"))
        print("SELECTED USER NAME FOR SUSPENSION: ", selected_user)
        selected_user_obj = User.objects.get(pk=selected_user)
        print("SELCTED USER OBJ for SUSPENSION: ", selected_user_obj, type(selected_user_obj))
        selected_user_obj.is_active=True
        selected_user_obj.save()
        return redirect('index.views.Home')

    else:
        suspension_form = SuspensionForm()
        unsuspension_form = UnsuspensionForm()

    return render(request, 'index/suspension.html', {'suspension_form': suspension_form, 'unsuspension_form': unsuspension_form})


def Register(request):
    context = RequestContext(request)
    registered = False

    if request.method == 'POST':
        user_form = UserForm(data=request.POST)

        if user_form.is_valid() :
            user = user_form.save()
            user.set_password(user.password)

            # public_group = Group.objects.get(name='Public')
            public_group, created = Group.objects.get_or_create(name='Public')
            public_group.user_set.add(user)

            randomGen = Random.new().read
            genKey = RSA.generate(1024, randomGen)

            key = Key.objects.create(user=user,rKey=genKey,publicKey = genKey.publickey().exportKey(),privateKey = genKey.exportKey())

            # key = Key.objects.create()
            # key.user = user
            # key.rKey = genKey
            # key.publicKey = genKey.publickey().exportKey()
            # key.privateKey = genKey.exportKey()

            user.save()
            key.save()

            registered = True
            print("USER SUCCESS!")

            print("public key is: " + str(key.publicKey))
            print("private key is: " + str(key.privateKey))
            print("NOT EXPORT: str")
            return render(request, 'index/success_register.html', {'private_key': key.rKey.exportKey("PEM")})
            bin = key.rKey.exportKey("DER")
            #return render(request, 'index/success_register.html', {'private_key': hex(bin)})

        else:
            print("USER ERROR!")
    else:
        user_form = UserForm()


    # user_form = UserForm()
    return render(request, 'index/register.html', {'user_form': user_form})


######################BASIC SITE INTRO STUFF#####################################################################################

def GettingStarted(request):
    return render(request, "index/about.html", {})

def Mission(request):
    return render(request, "index/mission.html", {})

def Security(request):
    return render(request, "index/security.html", {})


class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = (permissions.IsAdminUser, )


class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    permission_classes = (permissions.IsAdminUser, )


class ReportViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows reports to be viewed or edited.
    """
    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    permission_classes = (IsOwnerOrInGroupOrReadOnly, )


def Contact(request):
    return render(request, "index/contact.html", {})
