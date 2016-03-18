
# include <iostream>
# include <fstream>
# include <iomanip>
# include <cstdlib>
# include <cstring>
# include <string>
 void eatline() { while(std::cin.get()!='\n')continue;}

struct data
{

	std::string interface;
	std::string exp;
};
const char * file ="radar.conf";


data read_info()
{
	using namespace std;
	string name,expr;
	data data_obj;
	
	cout<<fixed<<right;



	ifstream inf;
	inf.open(file, ios_base::in);
	
	if(inf.is_open()){
		cout<<"Contents of the file:"<<file<<endl;
		getline(inf,name);
		cout<<"\n\tInter face:"<<name;
		getline(inf,expr);
		cout<<"\n\tExpression:"<<expr;
		
		}
	inf.close();
	
	string choice;
	cout<<"\n\tDo you want to edit the configuration[y/n] ";
	
	getline(cin,choice);		
	if(choice=="y"){
	ofstream outf(file,ios_base::out);
	if(outf.is_open()){
		
			cout<<"\n\tEnter interface name";
		getline(cin,data_obj.interface);
        outf<<data_obj.interface<<"\n";
         	cout<<"\n\tEnter fileter expression\n";
		getline(cin,data_obj.exp);
		outf<<data_obj.exp<<"\n";
		outf.close();
	}else{
	
	cout<<"\n\t ERROR CANT READ FILE\n";
	}

	inf.clear();

	inf.open(file, ios_base::in);
		
	if(inf.is_open()){
		cout<<"Contents of the file:"<<file<<endl;
		getline(inf,name);
		
		cout<<"\n\tInter face:"<<name;
		getline(inf,expr);
		cout<<"\n\tExpression:"<<expr;
		
		}
        inf.close();
        }
	data_obj.interface=name;
	data_obj.exp=expr;	
	return data_obj;
}		
