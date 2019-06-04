

/////////////////////////////////////////////////////////////////////////////
//
//                  文件隐藏 以及相关函数的实现
//
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////////////////////////////
//****************************************************************************************************
//文件隐藏需要增加的全局变量
LIST_ENTRY		g_HideObjHead;			//隐藏列表

//文件隐藏需要增加的函数

/*
*	测试是否是要隐藏的对象
*/
BOOLEAN
IS_MY_HIDE_OBJECT(const WCHAR *Name, ULONG NameLenth, ULONG Flag,PHIDE_DIRECTOR temHideDir)
{
	PLIST_ENTRY headListEntry = &(temHideDir->link);
	PLIST_ENTRY tmpListEntry = headListEntry;
	PHIDE_FILE tmpHideFile = NULL;
	ULONG ObjFlag = (FILE_ATTRIBUTE_DIRECTORY & Flag)?HIDE_FLAG_DIRECTORY:HIDE_FLAG_FILE;
	
	if (IsListEmpty(headListEntry))
	{
		return FALSE;
	}
	while (tmpListEntry->Flink != headListEntry)
	{
		tmpListEntry = tmpListEntry->Flink;
		tmpHideFile = (PHIDE_FILE)CONTAINING_RECORD(tmpListEntry, HIDE_FILE, linkfield);
		if ((ObjFlag == tmpHideFile->Flag) &&
			(0 == wcsncmp(Name, tmpHideFile->Name, NameLenth>>1)))
		{
			KdPrint(("Find Obj@=@=@=@=@=@=@=@=@=@&&&%%%^^^***###\n"));
			return TRUE;
		}
	}
	return FALSE;
}
VOID
AddHideObject(PHider addHide)
{
	//添加一个隐藏
	PHIDE_FILE newHideObj;
	PHIDE_DIRECTOR newHideDir;
	PLIST_ENTRY headListEntry = &g_HideObjHead;
	PLIST_ENTRY tmpListEntry = headListEntry;
	
	PHIDE_FILE tmpHideFile = NULL;
	PHIDE_DIRECTOR temHideDir = NULL;
	
	PWCHAR fatherPath=addHide->fatherpath;
	PWCHAR fileName=addHide->filename;
	PWCHAR hidAllPath=addHide->hiddenallpath;

    ULONG Flag;

	if (addHide->flag==HIDE_FLAG_DIRECTORY)
	{
		Flag=HIDE_FLAG_DIRECTORY;
	} 
	else
	{
		Flag=HIDE_FLAG_FILE;
	}
	
	//为新增加的隐藏路径申请内存
	newHideObj = ExAllocatePoolWithTag(PagedPool, sizeof(HIDE_FILE), 'NHFO');
	newHideDir = ExAllocatePoolWithTag(PagedPool, sizeof(HIDE_DIRECTOR), 'NHFO');
	
	InitializeListHead(&(newHideDir->link));
	
	//获取其标志位
	newHideObj->Flag = Flag;
	
	//拷贝名称到我们的数据结构中
	wcscpy(newHideDir->fatherPath, fatherPath);
	wcscpy(newHideObj->Name, fileName);
	
	//listentry增加一个成员
	//InsertTailList(&g_HideObjHead, &newHideObj->linkfield);
	
	//把隐藏文件的全路径加入到列表中
	SfAddComPathHidAce(hidAllPath);
	
	//如果列表的父目录为空，则说明列表中没有，直接插入就行了
	if (IsListEmpty(&g_HideObjHead))
	{
		InsertTailList(&g_HideObjHead, &newHideDir->linkfield);
		InsertTailList(&(newHideDir->link), &newHideObj->linkfield);
		return;
	}
	
	//另外就是原来表中已经有元素了，应该遍历查找，再插入
    while (tmpListEntry->Flink != headListEntry)//遍历整个父目录列表
	{
		//遍历父列表，取出他们所有的值
		tmpListEntry = tmpListEntry->Flink;
		temHideDir = (PHIDE_DIRECTOR)CONTAINING_RECORD(tmpListEntry, HIDE_DIRECTOR, linkfield);
		tmpHideFile = (PHIDE_FILE)CONTAINING_RECORD((temHideDir->link.Flink), HIDE_FILE, linkfield);
		
        if (!wcscmp(temHideDir->fatherPath,fatherPath))
		{
			//还是一样，应为应用层已经判断，添加不可能是重复路径，所以就不用判断了，
			//直接在在这个节点处插入
			InsertTailList(&(temHideDir->link), &newHideObj->linkfield);
			return;
		}
	}
	//如果有机会出循环就是说遍历了所有没有找到，则在后面插入
	InsertTailList(&g_HideObjHead, &newHideDir->linkfield);
	InsertTailList(&(newHideDir->link), &newHideObj->linkfield);
	return;
}

BOOLEAN
HandleDirectory(IN OUT PFILE_BOTH_DIR_INFORMATION DirInfo, //文件目录的信息
		IN PULONG lpBufLenth,PHIDE_DIRECTOR temHideDir)//长度
{
	//处理目录操作
	PFILE_BOTH_DIR_INFORMATION currentDirInfo = DirInfo;
	PFILE_BOTH_DIR_INFORMATION lastDirInfo = NULL;
	ULONG offset = 0;
	ULONG position = 0;
	ULONG newLenth = *lpBufLenth;
	//	WCHAR fileName[] = L"Test.txt";
	do
	{
		offset = currentDirInfo->NextEntryOffset;//得到下一个的偏移  也就是这个目录中的下一个文件地址
		//if (!(FILE_ATTRIBUTE_DIRECTORY & currentDirInfo->FileAttributes) &&
		//	 (0 == wcsncmp(currentDirInfo->FileName, fileName, currentDirInfo->FileNameLength>>1)))
		//查看是否为我们的隐藏对象
		if (IS_MY_HIDE_OBJECT(currentDirInfo->FileName,//文件名 
			currentDirInfo->FileNameLength,//文件名的长度
			currentDirInfo->FileAttributes,temHideDir))//文件属性
		{
			if (0 == offset)//没有其他的文件对象了
			{
				if (lastDirInfo)//若lastDirInfo不为空
				{
					lastDirInfo->NextEntryOffset = 0;//lastDirInfo指向的文件偏移设为为0
					newLenth -= *lpBufLenth - position;//新的长度计算
				}
				else
				{
					currentDirInfo->NextEntryOffset = 0;//currentDirInfo指向的文件偏移设为为0
					*lpBufLenth = 0;//新长度为0
					return TRUE;//函数返回
				}
			}
			else//就是还有下一个文件
			{
				//KdPrint(("n[%d][%d][%d]\n", newLenth, *lpBufLenth, position));
				RtlMoveMemory(currentDirInfo, (PUCHAR)currentDirInfo + offset, *lpBufLenth - position - offset);
				newLenth -= offset;
				position += offset;
			}
		}
		else//若不是就放过了  查看下一个对象
		{
			position += offset;
			lastDirInfo = currentDirInfo;
			currentDirInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)currentDirInfo + offset);
		}
	} while (0 != offset);
	*lpBufLenth = newLenth;
	return TRUE;
}

VOID
DelHideObject(PHider delHide)
{
	PLIST_ENTRY headListEntry = &g_HideObjHead;
	PLIST_ENTRY tmpListEntry = headListEntry;
	
	PLIST_ENTRY HideList = NULL;
	PLIST_ENTRY tmpHideList = NULL;
	
	PHIDE_FILE tmpHideFile = NULL;
	PHIDE_DIRECTOR temHideDir = NULL;
    PHIDE_FILE compareHideFile = NULL;
	
	//把应用层传过来的结构体读出来
	PWCHAR fatherPath=delHide->fatherpath;
	PWCHAR fileName=delHide->filename;
	PWCHAR hidAllPath=delHide->hiddenallpath;
    ULONG Flag;
	if (delHide->flag==HIDE_FLAG_DIRECTORY)
	{
		Flag=HIDE_FLAG_DIRECTORY;
	} 
	else
	{
		Flag=HIDE_FLAG_FILE;
	}
	SfDeleteComPathHidAce(hidAllPath);
	//如果列表的父目录为空，则说明列表中没有，直接返回
	if (IsListEmpty(&g_HideObjHead))
	{
		return;
	}
	
	//另外就是原来表中已经有元素了，应该遍历查找
    while (tmpListEntry->Flink != headListEntry)//遍历整个父目录列表
	{
		//遍历父列表，取出他们所有的值
		tmpListEntry = tmpListEntry->Flink;
		temHideDir = (PHIDE_DIRECTOR)CONTAINING_RECORD(tmpListEntry, HIDE_DIRECTOR, linkfield);
		tmpHideFile = (PHIDE_FILE)CONTAINING_RECORD((temHideDir->link.Flink), HIDE_FILE, linkfield);
		
		//如果找到父目录相同，应该遍历整个子目录查找是否存在要删除的节点
        if (!wcscmp(temHideDir->fatherPath,fatherPath))
		{
			HideList=&(temHideDir->link);
			tmpHideList=HideList;
			
			while (tmpHideList->Flink != HideList)
			{
				tmpHideList = tmpHideList->Flink;
				compareHideFile = (PHIDE_FILE)CONTAINING_RECORD(tmpHideList, HIDE_FILE, linkfield);
				if ((Flag == compareHideFile->Flag) &&
					(0 == wcsncmp(fileName, compareHideFile->Name, sizeof(fileName))))
				{
					//找到了，删除它
					RemoveEntryList((PLIST_ENTRY)compareHideFile);
					ExFreePool(compareHideFile);
					if (IsListEmpty(HideList))
					{
						//如果子链表为空是，则删除父项
						RemoveEntryList((PLIST_ENTRY)temHideDir);
						ExFreePool(temHideDir);
					}
					return;
				}
			}
		}
	}
	//如果有机会出循环就是说遍历了所有没有找到，则返回
	return;
}
