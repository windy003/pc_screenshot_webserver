package com.example.screenshotviewer

import android.graphics.BitmapFactory
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request

class ImageAdapter(
    private var images: List<FileItem>,
    private val baseUrl: String,
    private val onImageClick: (FileItem) -> Unit,
    private val onDownloadClick: (FileItem) -> Unit,
    private val onDeleteClick: (FileItem) -> Unit
) : RecyclerView.Adapter<ImageAdapter.ImageViewHolder>() {

    class ImageViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val imageView: ImageView = view.findViewById(R.id.imageView)
        val imageName: TextView = view.findViewById(R.id.imageName)
        val downloadButton: Button = view.findViewById(R.id.downloadButton)
        val deleteButton: Button = view.findViewById(R.id.deleteButton)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ImageViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_image, parent, false)
        return ImageViewHolder(view)
    }

    override fun onBindViewHolder(holder: ImageViewHolder, position: Int) {
        val item = images[position]
        holder.imageName.text = item.name

        // 显示placeholder
        holder.imageView.setImageResource(android.R.drawable.ic_menu_gallery)

        // 使用OkHttp + BitmapFactory加载图片
        val imageUrl = "$baseUrl/stream/${item.path}"
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val client = RetrofitClient.getOkHttpClient()
                val request = Request.Builder().url(imageUrl).build()
                val response = client.newCall(request).execute()

                if (response.isSuccessful) {
                    val inputStream = response.body?.byteStream()
                    val bitmap = BitmapFactory.decodeStream(inputStream)

                    withContext(Dispatchers.Main) {
                        if (bitmap != null) {
                            holder.imageView.setImageBitmap(bitmap)
                        } else {
                            holder.imageView.setImageResource(android.R.drawable.ic_menu_close_clear_cancel)
                        }
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        holder.imageView.setImageResource(android.R.drawable.ic_menu_close_clear_cancel)
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
                withContext(Dispatchers.Main) {
                    holder.imageView.setImageResource(android.R.drawable.ic_menu_close_clear_cancel)
                }
            }
        }

        holder.imageView.setOnClickListener { onImageClick(item) }
        holder.downloadButton.setOnClickListener { onDownloadClick(item) }
        holder.deleteButton.setOnClickListener { onDeleteClick(item) }
    }

    override fun getItemCount() = images.size

    fun updateImages(newImages: List<FileItem>) {
        images = newImages
        notifyDataSetChanged()
    }
}
