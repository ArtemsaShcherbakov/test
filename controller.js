import {
  loadTask,
  addTaskInList,
  deleteTaskFromList,
  editTaskFromList,
  saveEditTask,
  deleteAllTasks,
} from '../Model/model';
import {
  bindAddButton,
  bindDeleteAllButtons,
  bindDeleteAndEditButtons,
  deleteAllTaskView,
  addEventListenerOnNode,
  showAllTasks,
  addTask,
  getDescriptionFromInput,
  deleteTaskView,
  getIdTask,
  getEditedDescriptionTask,
  cancelEditingView,
  editTaskView,
  saveEditView,
} from '../View/view';

const eventManager = new Map();

export const initialize = () => {
  showList();
  bindAddButton(addOneTask);
  bindDeleteAllButtons(deleteAllListTasks);
  bindDeleteAndEditButtons(deleteOneTask, editTask);
};

const showList = () => {
  const listTasks = loadTask();

  showAllTasks(listTasks);
};

export const addOneTask = () => {
  const descriptionTask = getDescriptionFromInput();

  const task = addTaskInList(descriptionTask);

  if (!task) return;

  addTask(task);

  addEventListenerOnNode(null, deleteOneTask, editTask);
};

const deleteOneTask = index => {
  const taskId = deleteTaskView(index, 'click', eventManager.get(index));
  eventManager.delete(index);

  deleteTaskFromList(taskId);
};

const deleteAllListTasks = () => {
  deleteAllTasks();
  deleteAllTaskView();
};

const saveEdit = (taskId, index) => {
  const newDescription = getEditedDescriptionTask();

  const editedTask = saveEditTask(taskId, newDescription);

  saveEditView(taskId, editedTask);
  addEventListenerOnNode(index, deleteOneTask, editTask);
};

const cancelEditing = (taskId, textTask, index) => {
  cancelEditingView(taskId, textTask);
  addEventListenerOnNode(index, deleteOneTask, editTask);
};

const editTask = index => {
  const taskId = getIdTask(index);

  const textTask = editTaskView(taskId);

  if (textTask) {
    const buttonSaveEdit =
      document.getElementsByClassName('button-save-edit')[0];
    const buttonCancelEdit =
      document.getElementsByClassName('button-cancel-edit')[0];

    buttonSaveEdit.addEventListener('click', () => saveEdit(taskId, index), {
      once: true,
    });
    buttonCancelEdit.addEventListener(
      'click',
      () => cancelEditing(taskId, textTask, index),
      { once: true },
    );
  }

  editTaskFromList(taskId, textTask);
};
