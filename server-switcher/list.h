/*

   Copyright 2003 Jonathan Gallimore

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
   
*/

#include <windows.h>
#include <stdio.h>

typedef struct Element
{
	char* item;
	Element* next;
} Element;

class List
{
	public:

		List (void);
		~List (void);
		void addItem (char* item);
		void clear (void);
		int getCount (void);
		char* getFirst (void);
		char* getNext (void);

	private:

		Element* firstItem;
		Element* lastItem;
		Element* ptr;
		int count;
		char* res;

};

List::List (void)
{
	count = 0;
	firstItem = NULL;
	lastItem = NULL;
}

List::~List (void)
{
	this->clear ();
}

void List::addItem (char* item)
{
	Element* pElement = (Element*) malloc (sizeof(Element));

	pElement->item = strdup (item);
	pElement->next = NULL;
	count++;

	if (firstItem == NULL)
		firstItem = pElement;

	if (lastItem == NULL)
		lastItem = pElement;
	else
	{
		lastItem->next = pElement;
		lastItem = pElement;
	}
}


void List::clear (void)
{
	Element* item;
	Element* temp;

	item = firstItem;
	while (item != NULL)
	{
		free (item->item);
		temp = item;
		item = item->next;
		free (temp);
	}

	firstItem = NULL;
	lastItem = NULL;
	ptr = NULL;

	count = 0;
}

char* List::getFirst (void)
{
	ptr = firstItem;

	if (ptr!=NULL)
		return (ptr->item);
	else
		return (NULL);
}

char* List::getNext (void)
{
	if (ptr->next != NULL)
	{
		ptr = ptr->next;
		return (ptr->item);
	}
	else
		return (NULL);
}

int List::getCount (void)
{
	return (count);
}

