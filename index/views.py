from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth import authenticate, logout
from django.http import HttpResponse, HttpResponseRedirect
from projectSite import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from reports.models import Report
from .forms import ReportForm, UserForm
from django.template import RequestContext, loader
from django.utils import timezone



def Login(request):
    next = request.GET.get('next', '/home/')
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
    return render(request, "index/home.html", {})



@login_required
def ReportList(request):
    reports_list = Report.objects.order_by('title')[:5]
    print(reports_list)
    template = loader.get_template('index/report.html')
    context = {'reports_list': reports_list}
    return render(request, 'index/report.html', context)

@login_required
def detail(request, report_id):
    r = get_object_or_404(Report, pk=report_id)
    return render(request, 'index/detail.html', {'r': r})


def Register(request):
    context = RequestContext(request)
    registered = False

    if request.method == 'POST':
        user_form = UserForm(data=request.POST)

        if user_form.is_valid() :
            user = user_form.save()
            user.set_password(user.password)
            user.save()
            registered = True
            print("USER SUCCESS!")
        else:
            print("USER ERROR!")
    else:
        user_form = UserForm()


    # user_form = UserForm()
    return render(request, 'index/register.html', {'user_form': user_form})



@login_required
def create(request):
    if request.method == "POST":
        form = ReportForm(request.POST)
        if form.is_valid():
            report = form.save(commit=False)
            report.created = timezone.now()
            report.save()
            return render(request, 'index/report.html')

    else:
        form = ReportForm
    return render(request, 'index/create.html', {'form': form})
